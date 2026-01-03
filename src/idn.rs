/*
IDN and punycode lookup logic. Expands Unicode confusables to ASCII candidates,
checks registration status, and returns mappings that explain character swaps.
*/
use anyhow::Result;
use idna::domain_to_unicode;
use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::types::{IdnResponse, IdnResult, PunyMapping};
use crate::whois;

const DEFAULT_MAX_NORMALIZED: usize = 2000;
const DEFAULT_MAX_WHOIS_CHECKS: usize = 200;
const DEFAULT_MAX_RESULTS: usize = 50;
const DEFAULT_MAX_RESULTS_TIMEOUT: usize = 5;
const DEFAULT_WHOIS_TIMEOUT_MS: u64 = 2500;

static MAPPINGS: Lazy<HashMap<String, Vec<String>>> = Lazy::new(|| {
    let data = include_str!("../data/puny-mappings.json");
    serde_json::from_str(data).expect("puny-mappings.json must be valid JSON")
});

pub fn lookup_idn(domain: &str) -> Result<IdnResponse> {
    let results = puny2url(domain)?;
    Ok(IdnResponse {
        q: domain.to_string(),
        ascii: false,
        puny: true,
        results,
    })
}

fn puny2url(idn_domain: &str) -> Result<Vec<IdnResult>> {
    puny2url_with_checker(idn_domain, whois::check_domain_registration)
}

fn puny2url_with_checker<F>(idn_domain: &str, checker: F) -> Result<Vec<IdnResult>>
where
    F: Fn(&str, u64) -> Result<(bool, bool)>,
{
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
    let mut results: Vec<IdnResult> = Vec::new();
    let mut timed_out = false;

    for (checks, domain) in normalized_domains.into_iter().enumerate() {
        if checks >= max_whois_checks {
            break;
        }
        if !timed_out && results.len() >= max_results {
            break;
        }
        if timed_out && results.len() >= max_results_timeout {
            break;
        }

        let (registered, lookup_timed_out) = checker(&domain, whois_timeout)?;

        if lookup_timed_out {
            timed_out = true;
        }

        if registered {
            results.push(IdnResult {
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
    if idn_domain.chars().any(|c| c.is_whitespace()) {
        return None;
    }
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
                unicode: unicode_char.to_string(),
                ascii: ascii_char.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn lookup_idn_expected_results_with_stubbed_whois() {
        let domain = "амаzоn.com";
        let result = lookup_idn_with_checker(domain, |candidate, _| {
            let registered = matches!(candidate, "amazon.com" | "amaz0n.com");
            Ok((registered, false))
        })
        .expect("lookup should succeed");

        let expected = json!({
            "q": "амаzоn.com",
            "ascii": false,
            "puny": true,
            "results": [
                {
                    "domain": "amazon.com",
                    "is_registered": true,
                    "mappings": [
                        { "ascii": "a", "unicode": "а" },
                        { "ascii": "m", "unicode": "м" },
                        { "ascii": "a", "unicode": "а" },
                        { "ascii": "o", "unicode": "о" }
                    ]
                },
                {
                    "domain": "amaz0n.com",
                    "is_registered": true,
                    "mappings": [
                        { "ascii": "a", "unicode": "а" },
                        { "ascii": "m", "unicode": "м" },
                        { "ascii": "a", "unicode": "а" },
                        { "ascii": "0", "unicode": "о" }
                    ]
                }
            ]
        });

        assert_eq!(serde_json::to_value(result).unwrap(), expected);
    }

    #[test]
    fn decode_idn_to_unicode_rejects_invalid() {
        assert!(decode_idn_to_unicode("bad domain").is_none());
    }

    #[test]
    fn normalize_domain_expands_confusables_with_limit() {
        let mut confusables = HashMap::new();
        confusables.insert("a".to_string(), vec!["a".to_string(), "@".to_string()]);
        confusables.insert("b".to_string(), vec!["b".to_string()]);

        let results = normalize_domain("ab", &confusables, 10);
        assert_eq!(results, vec!["ab".to_string(), "@b".to_string()]);
    }

    #[test]
    fn normalize_domain_respects_max_normalized() {
        let mut confusables = HashMap::new();
        confusables.insert("a".to_string(), vec!["a".to_string(), "@".to_string()]);
        confusables.insert("b".to_string(), vec!["b".to_string(), "8".to_string()]);
        let results = normalize_domain("ab", &confusables, 1);
        assert_eq!(results, vec!["a".to_string()]);
    }

    #[test]
    fn map_unicode_to_ascii_only_includes_non_ascii() {
        let mappings = map_unicode_to_ascii("аb", "ab");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].unicode, "а");
        assert_eq!(mappings[0].ascii, "a");
    }

    #[test]
    fn env_helpers_fall_back_on_invalid_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("PUNY_MAX_NORMALIZED", "not-a-number");
        std::env::set_var("WHOIS_TIMEOUT_MS", "oops");

        assert_eq!(env_usize("PUNY_MAX_NORMALIZED", 123), 123);
        assert_eq!(env_u64("WHOIS_TIMEOUT_MS", 456), 456);

        std::env::remove_var("PUNY_MAX_NORMALIZED");
        std::env::remove_var("WHOIS_TIMEOUT_MS");
    }

    fn lookup_idn_with_checker<F>(domain: &str, checker: F) -> Result<IdnResponse>
    where
        F: Fn(&str, u64) -> Result<(bool, bool)>,
    {
        let results = puny2url_with_checker(domain, checker)?;
        Ok(IdnResponse {
            q: domain.to_string(),
            ascii: false,
            puny: true,
            results,
        })
    }
}
