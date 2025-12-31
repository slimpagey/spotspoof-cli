use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct DnsResponse {
	Answer: Option<Vec<serde_json::Value>>,
}

pub fn check_domain_registration(domain: &str, timeout_ms: u64) -> Result<(bool, bool)> {
	let client = reqwest::blocking::Client::builder()
		.timeout(Duration::from_millis(timeout_ms))
		.build()?;

	let url = format!("https://dns.google/resolve?name={domain}&type=NS");
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
			let registered = data.Answer.map(|a| !a.is_empty()).unwrap_or(false);
			Ok((registered, false))
		}
		Err(err) => {
			let timed_out = err.is_timeout();
			Ok((false, timed_out))
		}
	}
}
