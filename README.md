# h3_fuzz

A multi-threaded HTTP/3 endpoint fuzzer written in Rust, built on top of [`quinn`](https://github.com/quinn-rs/quinn) and [`h3`](https://github.com/hyperium/h3). Highly inspired by [`ffuf`](https://github.com/ffuf/ffuf).

It sends requests to a target URL, substituting a `FUZZ` keyword in the path and/or query string with each entry of a wordlist, and reports response status codes, body length, and timing for each request.

## Features

- Native **HTTP/3 (QUIC)** support
- Concurrent requests with a configurable concurrency limit
- Multiple HTTP methods per run (`GET,POST,PUT,...`)
- Optional TLS certificate verification bypass (`-k` / `--insecure`) for testing against self-signed / internal targets
- Results summary (status code breakdown + min/avg/max response time)
- Optional CSV export of results

## Installation

```bash
 ╰─λ git clone https://github.com/mathieuemery/h3_fuzz.git
 ╰─λ cd h3_fuzz
 ╰─λ cargo build --release
```

The binary will be available at `target/release/h3_fuzz`.

## Usage

```bash
 ╰─λ ./h3_fuzz --url https://target.example.com/api/FUZZ \
       --wordlist wordlist.txt \
       --methods GET,POST \
       --concurrency 20 \
       --timeout 5 \
       --output results.csv
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL, must use `https://` and contain a `FUZZ` keyword in the path and/or query | required |
| `-w, --wordlist` | Path to a newline-separated wordlist file | required |
| `-X, --methods` | Comma-separated list of HTTP methods to try | `GET` |
| `-c, --concurrency` | Number of concurrent requests | `10` |
| `-t, --timeout` | Per-request timeout in seconds | `10.0` |
| `-o, --output` | Optional path to write results as CSV | none |
| `-k, --insecure` | Disable TLS certificate verification | disabled |

### Example

```bash
 ╰─λ ./h3_fuzz -u "https://example.com/FUZZ" -w common.txt -X GET,POST -c 25 -k
```

## Testing

Unit and integration tests cover the wordlist parsing, path/query substitution logic, CSV export, and the results summary computation:

```bash
 ╰─λ cargo test
```

## Disclaimer

This tool is intended for authorized security testing only (e.g. testing infrastructure you own or have explicit permission to test). Do not use it against systems without authorization.

## License

MIT