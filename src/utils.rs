//! Types, structures, constants and methods used by the fuzzer

use std::time::Duration;

use h3::client::SendRequest;
use tracing::debug;

use crate::fuzz::FuzzResult;

const MAX_HTTP_CODE: usize = 600;
type HttpCodeSummary = [usize; MAX_HTTP_CODE];
pub type FuzzRequest = SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// Fuzzing constants
pub const FUZZ_KEYWORD: &str = "FUZZ";
pub const MAX_RETRIES: usize = 10;
pub const DEFAULT_PORT: u16 = 443;

/// Stores the summary of the fuzz
struct Summary {
    counts: HttpCodeSummary,
    min_time: f64,
    max_time: f64,
    avg_time: f64,
}

/// Build the summary from the results
fn summarize(results: &[FuzzResult]) -> Summary {
    let mut summary = Summary {
        counts: [0usize; MAX_HTTP_CODE],
        min_time: f64::MAX,
        max_time: f64::MIN,
        avg_time: 0.0,
    };

    let mut total_time = 0.0;

    for r in results {
        if r.status >= 600 {
            debug!("Invalid status code {} for path: {}", r.status, r.path);
            continue;
        }
        summary.counts[r.status as usize] += 1;

        summary.min_time = summary.min_time.min(r.time_ms);
        summary.max_time = summary.max_time.max(r.time_ms);
        total_time += r.time_ms;
    }

    if !results.is_empty() {
        summary.avg_time = total_time / results.len() as f64;
    } else {
        summary.min_time = 0.0;
        summary.max_time = 0.0;
    }

    summary
}

/// Print the summary for this scan
pub fn print_summary(results: &[FuzzResult], elapsed: &Duration) {
    let s = summarize(&results);

    println!();
    println!("╭──────────────────────────────────────╮");
    println!("│            Fuzzing Summary           │");
    println!("╰──────────────────────────────────────╯");
    println!();

    println!("Requests sent        : {}", results.len());
    println!("Duration             : {:.2}s", elapsed.as_secs_f64());
    println!("Requests/sec         : {:.2}", results.len() as f64 / elapsed.as_secs_f64());

    println!();
    println!("Responses:");
    
    // Print codes
    for i in 0..MAX_HTTP_CODE {
        if s.counts[i] > 0 {
            match i {
                200..300 => println!("  \x1b[32m{}\x1b[0m                : {}", i, s.counts[i]),
                300..400 => println!("  \x1b[33m{}\x1b[0m                : {}", i, s.counts[i]),
                400..500 => println!("  \x1b[31m{}\x1b[0m                : {}", i, s.counts[i]),
                500..600 => println!("  \x1b[35m{}\x1b[0m                : {}", i, s.counts[i]),
                _ => {}
            }
        }
    }

    println!();
    println!("Timing:");
    println!("  Min response time  : {:.3} ms", s.min_time);
    println!("  Avg response time  : {:.3} ms", s.avg_time);
    println!("  Max response time  : {:.3} ms", s.max_time);

    println!();
    println!("\x1b[32mFuzzing completed\x1b[0m");
}


#[cfg(test)]
mod tests {
    use super::*;
 
    fn result(status: u16, time_ms: f64) -> FuzzResult {
        FuzzResult {
            method: "GET".to_string(),
            path: "/x".to_string(),
            status,
            len: 0,
            time_ms,
        }
    }
 
    #[test]
    fn summarize_counts_status_codes() {
        let results = vec![result(200, 10.0), result(200, 20.0), result(404, 5.0)];
        let s = summarize(&results);
        assert_eq!(s.counts[200], 2);
        assert_eq!(s.counts[404], 1);
        assert_eq!(s.counts[500], 0);
    }
 
    #[test]
    fn summarize_computes_min_max_avg_time() {
        let results = vec![result(200, 10.0), result(200, 20.0), result(200, 30.0)];
        let s = summarize(&results);
        assert_eq!(s.min_time, 10.0);
        assert_eq!(s.max_time, 30.0);
        assert!((s.avg_time - 20.0).abs() < f64::EPSILON);
    }
 
    #[test]
    fn summarize_handles_empty_results() {
        let s = summarize(&[]);
        assert_eq!(s.min_time, 0.0);
        assert_eq!(s.max_time, 0.0);
        assert_eq!(s.avg_time, 0.0);
        assert!(s.counts.iter().all(|&c| c == 0));
    }
 
    #[test]
    fn summarize_skips_invalid_status_codes() {
        let mut r = result(999, 5.0);
        r.status = 999; // invalid, out of the 0..600 range
        let results = vec![r, result(200, 1.0)];
        let s = summarize(&results);
        assert_eq!(s.counts[200], 1);
        // min/max/avg should only reflect the valid entry
        assert_eq!(s.min_time, 1.0);
        assert_eq!(s.max_time, 1.0);
    }
 
    #[test]
    fn summarize_single_result() {
        let results = vec![result(301, 7.5)];
        let s = summarize(&results);
        assert_eq!(s.counts[301], 1);
        assert_eq!(s.min_time, 7.5);
        assert_eq!(s.max_time, 7.5);
        assert_eq!(s.avg_time, 7.5);
    }
}