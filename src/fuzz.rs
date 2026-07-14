//! Fuzz the target using the provided wordlist

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use bytes::Buf;
use http::Method;
use tokio::sync::Semaphore;
use url::Url;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    files::WordList,
    utils::{FUZZ_KEYWORD, FuzzRequest, MAX_RETRIES},
};

/// Params required to start the fuzzing
pub struct FuzzParams {
    pub authority: String,
    pub wordlist: WordList,
    pub methods: Vec<Method>,
    pub url: Url,
    pub timeout: f64,
    pub concurrency: usize,
    pub host: String,
    pub port: u16,
}

/// Result of a request on an endpoint
#[derive(Deserialize, Serialize)]
pub struct FuzzResult {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub len: usize,
    pub time_ms: f64,
}

/// Build the path by replacing the keyword by the ones from the wordlist
fn build_path(template_path: &str, template_query: &str, word: &str) -> String {
    let path = template_path.replace(FUZZ_KEYWORD, word);
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    if !template_query.is_empty() {
        format!("{}?{}", path, template_query.replace(FUZZ_KEYWORD, word))
    } else {
        path
    }
}

/// Params used to do one request
struct TaskParams{
    timeout: Duration,
    method: Method,
    authority: String,
    path: String,
}

/// Send one request to the target
async fn send_one(
    mut send_request: FuzzRequest,
    params: &TaskParams
) -> anyhow::Result<(u16, usize)> {
    let uri = format!("https://{}{}", params.authority, params.path).parse::<http::Uri>()?;
    let req = http::Request::builder().method(params.method.clone()).uri(uri).body(())?;

    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    let status = resp.status().as_u16();

    let mut body_len = 0;
    while let Some(chunk) = stream.recv_data().await? {
        body_len += chunk.remaining();
    }

    Ok((status, body_len))
}

/// Handle one request
/// 
/// Retries are necessary as the target can reset the stream
async fn handle(send_request: FuzzRequest, params: TaskParams) -> Result<FuzzResult> {
    for attempt in 0..MAX_RETRIES {
        let start = Instant::now();

        // Send the request
        let result = tokio::time::timeout(
            params.timeout,
            send_one(
                send_request.clone(),
                &params
            ),
        )
        .await;

        let elapsed = start.elapsed();
        let time_ms = elapsed.as_secs_f64() * 1000.0;

        match result {
            Ok(Ok((status, len))) => {
                // Print the result of the request
                println!( "{0:6} {1:40} -> status={2:?} len={3} time={4:.3?}", params.method, params.path, status, len, time_ms );
                return Ok(FuzzResult {
                    method: params.method.to_string(),
                    path: params.path.clone(),
                    status,
                    len,
                    time_ms,
                });
            }

            Ok(Err(e)) => {
                debug!("Attempt {} failed for {}: {}", attempt + 1, params.path, e);
            }

            Err(e) => {
                debug!("Timeout on attempt {} for {}: {}", attempt + 1, params.path, e);
            }
        }
    }

    bail!("Request for {} failed after retries", params.path)
}

/// Fuzz the target by trying all possible requests
pub async fn fuzz_target(send_request: FuzzRequest, params: FuzzParams) -> Result<Vec<FuzzResult>> {
    // Semaphore to limit the number of concurrent requests
    let sem = Arc::new(Semaphore::new(params.concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    let mut result: Vec<FuzzResult> = Vec::new();

    // Iterate over the wordlist to do all the requests
    for word in params.wordlist.words() {
        for method in &params.methods {
            let sem = sem.clone();
            let send_request = send_request.clone();
            let authority = params.authority.clone();
            let path = build_path(params.url.path(), params.url.query().unwrap_or(""), word);
            let method = method.clone();
            let timeout = Duration::from_secs_f64(params.timeout);

            tasks.spawn(async move {
                let _permit = sem.acquire().await?;
                 handle(send_request, TaskParams { timeout, method, authority, path }).await
            });
        }
    }

    while let Some(res) = tasks.join_next().await {
        let fuzz_res = res??;
        result.push(fuzz_res)
    }

    Ok(result)
}


#[cfg(test)]
mod tests {
    use super::*;
 
    #[test]
    fn build_path_replaces_keyword_in_path() {
        let path = build_path("/api/FUZZ", "", "admin");
        assert_eq!(path, "/api/admin");
    }
 
    #[test]
    fn build_path_replaces_keyword_in_query() {
        let path = build_path("/search", "id=FUZZ", "1");
        assert_eq!(path, "/search?id=1");
    }
 
    #[test]
    fn build_path_replaces_keyword_in_both_path_and_query() {
        let path = build_path("/api/FUZZ", "sort=FUZZ", "users");
        assert_eq!(path, "/api/users?sort=users");
    }
 
    #[test]
    fn build_path_defaults_to_slash_when_result_is_empty() {
        let path = build_path("", "", "word");
        assert_eq!(path, "/");
    }
 
    #[test]
    fn build_path_leaves_path_untouched_without_query() {
        let path = build_path("/static/FUZZ.html", "", "index");
        assert_eq!(path, "/static/index.html");
    }
 
    #[test]
    fn build_path_ignores_empty_query_string() {
        let path = build_path("/FUZZ", "", "test");
        assert_eq!(path, "/test");
    }
 
    #[test]
    fn build_path_no_keyword_present_is_unchanged() {
        let path = build_path("/static/page", "a=1", "ignored");
        assert_eq!(path, "/static/page?a=1");
    }
}