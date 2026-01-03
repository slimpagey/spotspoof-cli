/*
DNS registration checks used by IDN lookups. Calls a DNS-over-HTTPS resolver
to determine whether candidate domains are registered.
*/
use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<serde_json::Value>>,
}

pub fn check_domain_registration(domain: &str, timeout_ms: u64) -> Result<(bool, bool)> {
    check_domain_registration_with_url(domain, timeout_ms, "https://dns.google/resolve")
}

fn check_domain_registration_with_url(
    domain: &str,
    timeout_ms: u64,
    base_url: &str,
) -> Result<(bool, bool)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    let url = format!("{base_url}?name={domain}&type=NS");
    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send();

    match resp {
        Ok(response) => {
            if !response.status().is_success() {
                return Ok((false, false));
            }
            let data: DnsResponse = response.json()?;
            let registered = data.answer.map(|a| !a.is_empty()).unwrap_or(false);
            Ok((registered, false))
        }
        Err(err) => {
            let timed_out = err.is_timeout();
            Ok((false, timed_out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn start_server(
        response: Vec<u8>,
        expected_method: &str,
        expected_path_prefix: &str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let expected_method = expected_method.to_string();
        let expected_path_prefix = expected_path_prefix.to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let read = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]);
                let ok = request
                    .lines()
                    .next()
                    .map(|line| {
                        line.starts_with(&format!("{expected_method} {expected_path_prefix}"))
                    })
                    .unwrap_or(false);
                if ok {
                    let _ = stream.write_all(&response);
                } else {
                    let _ =
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
            }
        });
        format!("http://{addr}/resolve")
    }

    #[test]
    fn check_domain_registration_parses_success() {
        let body =
            r#"{"Answer":[{"name":"example.com","type":2,"TTL":300,"data":"ns1.example.com."}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes();
        let url = start_server(response, "GET", "/resolve?");
        let (registered, timed_out) =
            check_domain_registration_with_url("example.com", 1000, &url).unwrap();
        assert!(registered);
        assert!(!timed_out);
    }

    #[test]
    fn check_domain_registration_handles_non_success() {
        let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
        let url = start_server(response, "GET", "/resolve?");
        let (registered, timed_out) =
            check_domain_registration_with_url("example.com", 1000, &url).unwrap();
        assert!(!registered);
        assert!(!timed_out);
    }
}
