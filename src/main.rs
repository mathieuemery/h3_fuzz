use std::{
    net::SocketAddr,
    time::Instant,
    sync::Arc
};

use anyhow::{Result, anyhow};
use clap::Parser;
use h3_quinn::quinn;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

use crate::{
    cert_verifier::CustomVerifier,
    files::{
        WordList,
        write_to_disk
    },
    fuzz::{
        FuzzParams,
        fuzz_target,
    },
    utils::{DEFAULT_PORT, print_summary}
};

mod cert_verifier;
mod files;
mod fuzz;
mod utils;

/// Stores the CLI params from the client
#[derive(Parser, Debug)]
#[command(
    author = "Mathieu Emery",
    version,
    about = "Multi-threaded HTTP/3 endpoint fuzzer."
)]
struct Args {
    #[arg(short = 'u', long)]
    url: String,
    #[arg(short = 'w', long)]
    wordlist: String,
    #[arg(short = 'X', long, default_value = "GET")]
    methods: String,
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    #[arg(short = 't', long, default_value_t = 10.0)]
    timeout: f64,
    #[arg(short = 'o', long)]
    output: Option<String>,
    #[arg(short = 'k', long)]
    insecure: bool,
}

/// Convert the CLI params to Fuzz params
impl TryFrom<&Args> for FuzzParams {
    type Error = anyhow::Error;

    fn try_from(args: &Args) -> Result<Self, Self::Error> {
        let url = Url::parse(&args.url)?;
        if url.scheme() != "https" {
            anyhow::bail!("HTTP/3 requires https://");
        }

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("Couldn't extract the host from the URL"))?
            .to_string();

        let port = url.port().unwrap_or(DEFAULT_PORT);

        let authority = if url.port().is_some() {
            format!("{host}:{port}")
        } else {
            host.clone()
        };

        let wordlist = WordList::new(&args.wordlist)?;

        let methods = args
            .methods
            .split(',')
            .map(|m| m.trim().parse())
            .collect::<Result<Vec<http::Method>, _>>()?;

        Ok(Self {
            authority,
            wordlist,
            methods,
            url,
            timeout: args.timeout,
            concurrency: args.concurrency,
            host,
            port,
        })
    }
}

/// Init the logging system
fn init_logs() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).init();
}

/// Create a QUIC endpoint for the client
async fn make_endpoint(insecure: bool) -> anyhow::Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    if insecure {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(CustomVerifier::new()));
    }
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    init_logs();

    let args = Args::parse();
    let params = FuzzParams::try_from(&args)?;

    let endpoint = make_endpoint(args.insecure).await?;
    let addr: SocketAddr = tokio::net::lookup_host((params.host.as_str(), params.port))
        .await?
        .next()
        .unwrap();

    let conn = endpoint.connect(addr, &params.host)?.await?;
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    // Drive the connection in the background so it stays open
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let start = Instant::now();
    let results = fuzz_target(send_request, params).await?;
    let elapsed = start.elapsed();

    print_summary(&results, &elapsed);

    // Write the results to disk if asked
    if let Some(out) = args.output {
        write_to_disk(&results, &out)?;

        println!("\nResults saved to:");
        println!("  {}", out);
    }

    Ok(())
}
