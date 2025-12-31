use anyhow::Result;
use idna::domain_to_unicode;
use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

use crate::whois;

const DEFAULT_MAX_NORMALIZED: usize = 2000;
const DEFAULT_MAX_WHOIS_CHECKS: usize = 200;
const DEFAULT_MAX_RESULTS: usize = 50;
const DEFAULT_MAX_RESULTS_TIMEOUT: usize = 5;
const DEFAULT_WHOIS_TIMEOUT_MS: u64 = 2500;

#[derive(Debug, Serialize)]
struct PunyMapping {
	unicode: char,
	ascii: char,
}

#[derive(Debug, Serialize)]
struct PunyResult {
	domain: String,
	mappings: Vec<PunyMapping>,
	is_registered: bool,
}

static MAPPINGS: Lazy<HashMap<String, Vec<String>>> = Lazy::new(|| {
	let data = include_str!("../data/puny-mappings.json");
	serde_json::from_str(data).expect("puny-mappings.json must be valid JSON")
});

pub fn lookup_idn(domain: &str) -> Result<serde_json::Value> {
	let results = puny2url(domain)?;
	Ok(json!({ "q": domain, "ascii": false, "puny": true, "results": results }))
}

fn puny2url(idn_domain: &str) -> Result<Vec<PunyResult>> {
	let unicode_domain = decode_idn_to_unicode(idn_domain);
	let Some(unicode_domain) = unicode_domain else {
		return Ok(Vec::new());
	};

	let max_normalized = env_usize("PUNY_MAX_NORMALIZED", DEFAULT_MAX_NORMALIZED);
	let max_whois_checks = env_usize("WHOIS_MAX_CHECKS", DEFAULT_MAX_WHOIS_CHECKS);
	let max_results = env_usize("PUNY_MAX_RESULTS", DEFAULT_MAX_RESULTS);
	let max_results_timeout = env_usize("PUNY_MAX_RESULTS_TIMEOUT", DEFAULT_MAX_RESULTS_TIMEOUT);
	let whois_timeout = env_u64("WHOIS_TIMEOUT_MS", DEFAULT_WHOIS_TIMEOUT_MS);

	let normalized_domains = normalize_domain(&unicode_domain, &MAPPINGS, max_normalized);
	let mut results: Vec<PunyResult> = Vec::new();
	let mut timed_out = false;
	let mut checks = 0usize;

	for domain in normalized_domains {
		if checks >= max_whois_checks {
			break;
		}
		if !timed_out && results.len() >= max_results {
			break;
		}
		if timed_out && results.len() >= max_results_timeout {
			break;
		}

		checks += 1;
		let (registered, lookup_timed_out) = whois::check_domain_registration(&domain, whois_timeout)?;

		if lookup_timed_out {
			timed_out = true;
		}

		if registered {
			results.push(PunyResult {
				domain: domain.clone(),
				mappings: map_unicode_to_ascii(&unicode_domain, &domain),
				is_registered: true,
			});
		}

		if timed_out {
			break;
		}
	}

	if timed_out && results.len() > max_results_timeout {
		results.truncate(max_results_timeout);
	}

	Ok(results)
}

fn decode_idn_to_unicode(idn_domain: &str) -> Option<String> {
	let (unicode, errors) = domain_to_unicode(idn_domain);
	if errors.is_err() {
		return None;
	}
	Some(unicode)
}

fn normalize_domain(
	domain: &str,
	confusables: &HashMap<String, Vec<String>>,
	max_normalized: usize,
) -> Vec<String> {
	let mut combinations = vec![String::new()];

	for ch in domain.chars() {
		let key = ch.to_string();
		let replacements = confusables.get(&key).cloned().unwrap_or_else(|| vec![key]);
		let mut next = Vec::new();

		for prefix in combinations.iter() {
			for replacement in replacements.iter() {
				if next.len() >= max_normalized {
					break;
				}
				let mut combined = prefix.clone();
				combined.push_str(replacement);
				next.push(combined);
			}
			if next.len() >= max_normalized {
				break;
			}
		}

		combinations = next;
		if combinations.len() >= max_normalized {
			break;
		}
	}

	combinations
}

fn map_unicode_to_ascii(unicode_domain: &str, normalized_domain: &str) -> Vec<PunyMapping> {
	let unicode_chars: Vec<char> = unicode_domain.chars().collect();
	let ascii_chars: Vec<char> = normalized_domain.chars().collect();
	let mut mappings = Vec::new();
	let len = unicode_chars.len().min(ascii_chars.len());

	for i in 0..len {
		let unicode_char = unicode_chars[i];
		let ascii_char = ascii_chars[i];
		if (unicode_char as u32) > 127 {
			mappings.push(PunyMapping {
				unicode: unicode_char,
				ascii: ascii_char,
			});
		}
	}

	mappings
}

fn env_usize(key: &str, default: usize) -> usize {
	std::env::var(key)
		.ok()
		.and_then(|v| v.parse::<usize>().ok())
		.unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
	std::env::var(key)
		.ok()
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(default)
}
