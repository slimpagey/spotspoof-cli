use anyhow::Result;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashSet;

use crate::db;
use crate::types::{AsciiResponse, AsciiResult};

const LENGTH_BAND: usize = 2;
const MAX_CANDIDATES: usize = 5000;
const MIN_SIMILARITY: u8 = 80;
const MAX_RESULTS: usize = 3;

#[derive(Debug, Deserialize)]
struct MostPhishedEntry {
	domain: String,
	base: String,
	#[serde(default)]
	aliases: Vec<String>,
}

static MOST_PHISHED: Lazy<Vec<MostPhishedEntry>> = Lazy::new(|| {
	let data = include_str!("../data/most-phished.json");
	serde_json::from_str(data).expect("most-phished.json must be valid JSON")
});

pub fn lookup_ascii(domain: &str, db_path: &str) -> Result<AsciiResponse> {
	let results = detect_impersonation(domain, db_path)?;
	Ok(AsciiResponse {
		q: domain.to_string(),
		ascii: true,
		puny: false,
		results,
	})
}

fn detect_impersonation(domain: &str, db_path: &str) -> Result<Vec<AsciiResult>> {
	let most_phished_results = detect_from_most_phished(domain);
	if !most_phished_results.is_empty() {
		return Ok(most_phished_results);
	}

	let normalized = normalize(domain);
	let first_char = normalized.chars().next();
	let length = normalized.len();

	if first_char.is_none() {
		return Ok(Vec::new());
	}

	let conn = db::open(db_path)?;
	let candidates = db::fetch_candidates(
		&conn,
		first_char.unwrap(),
		length.saturating_sub(LENGTH_BAND),
		length + LENGTH_BAND,
		MAX_CANDIDATES,
	)?;

	let mut scored: Vec<AsciiResult> = candidates
		.into_iter()
		.map(|candidate| {
			let similarity = similarity_ratio(&normalized, &candidate);
			AsciiResult {
				domain: candidate,
				similarity,
			}
		})
		.filter(|result| result.similarity >= MIN_SIMILARITY)
		.collect();

	scored.sort_by(|a, b| b.similarity.cmp(&a.similarity));
	scored.truncate(MAX_RESULTS);
	Ok(scored)
}

fn detect_from_most_phished(domain: &str) -> Vec<AsciiResult> {
	let input = normalize(domain);
	let input_base = get_base_domain(&input);
	let mut candidates = HashSet::new();
	candidates.insert(input.clone());
	candidates.insert(input_base.clone());
	candidates.insert(strip_non_alnum(&input));
	candidates.insert(strip_non_alnum(&input_base));

	let mut results = Vec::new();

	for entry in MOST_PHISHED.iter() {
		let mut entry_targets = HashSet::new();
		entry_targets.insert(entry.domain.as_str());
		entry_targets.insert(entry.base.as_str());
		for alias in &entry.aliases {
			entry_targets.insert(alias.as_str());
		}

		let mut best: u8 = 0;
		for candidate in candidates.iter() {
			for target in entry_targets.iter() {
				let score = similarity_ratio(candidate, target);
				if score > best {
					best = score;
				}
			}
		}

		if best >= MIN_SIMILARITY {
			results.push(AsciiResult {
				domain: entry.domain.clone(),
				similarity: best,
			});
		}
	}

	results.sort_by(|a, b| b.similarity.cmp(&a.similarity));
	results.truncate(MAX_RESULTS);
	results
}

fn normalize(value: &str) -> String {
	value.to_lowercase()
}

fn strip_non_alnum(value: &str) -> String {
	value.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

fn get_base_domain(domain: &str) -> String {
	match domain.rfind('.') {
		Some(idx) if idx > 0 => domain[..idx].to_string(),
		_ => domain.to_string(),
	}
}

fn similarity_ratio(a: &str, b: &str) -> u8 {
	let max_len = a.len().max(b.len());
	if max_len == 0 {
		return 100;
	}
	let distance = levenshtein_distance(a, b);
	let ratio = 1.0 - (distance as f32 / max_len as f32);
	(100.0 * ratio).round().max(0.0) as u8
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
	if a == b {
		return 0;
	}
	let a_len = a.len();
	let b_len = b.len();
	if a_len == 0 {
		return b_len;
	}
	if b_len == 0 {
		return a_len;
	}

	let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];
	for i in 0..=a_len {
		matrix[i][0] = i;
	}
	for j in 0..=b_len {
		matrix[0][j] = j;
	}

	for (i, ca) in a.as_bytes().iter().enumerate() {
		for (j, cb) in b.as_bytes().iter().enumerate() {
			let cost = if ca == cb { 0 } else { 1 };
			matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
				.min(matrix[i + 1][j] + 1)
				.min(matrix[i][j] + cost);
		}
	}

	matrix[a_len][b_len]
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn lookup_ascii_returns_expected_for_gooble() {
		let result = lookup_ascii("gooble.com", "unused.sqlite").expect("lookup should succeed");
		let expected = json!({
			"q": "gooble.com",
			"ascii": true,
			"puny": false,
			"results": [
				{
					"domain": "google.com",
					"similarity": 90
				}
			]
		});
		assert_eq!(serde_json::to_value(result).unwrap(), expected);
	}

	#[test]
	fn similarity_ratio_handles_edge_cases() {
		assert_eq!(similarity_ratio("", ""), 100);
		assert_eq!(similarity_ratio("a", ""), 0);
		assert_eq!(similarity_ratio("same", "same"), 100);
	}

	#[test]
	fn levenshtein_distance_basic_cases() {
		assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
		assert_eq!(levenshtein_distance("", "abc"), 3);
		assert_eq!(levenshtein_distance("abc", ""), 3);
	}

	#[test]
	fn detect_from_most_phished_matches_base_domain() {
		let results = detect_from_most_phished("gooble");
		assert!(results.iter().any(|r| r.domain == "google.com"));
	}

	#[test]
	fn normalize_and_helpers() {
		assert_eq!(normalize("TeSt.COM"), "test.com");
		assert_eq!(strip_non_alnum("g00-gle.com"), "g00glecom");
		assert_eq!(get_base_domain("example.com"), "example");
		assert_eq!(get_base_domain("nodot"), "nodot");
	}
}
