/*
Shared request/response models for CLI and HTTP APIs. Includes lightweight
validation helpers to round-trip serialize/deserialize for sanity checks.
*/
use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct LookupRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct HealthzResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct AsciiResponse {
    pub q: String,
    pub ascii: bool,
    pub puny: bool,
    pub results: Vec<AsciiResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct AsciiResult {
    pub domain: String,
    pub similarity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct IdnResponse {
    pub q: String,
    pub ascii: bool,
    pub puny: bool,
    pub results: Vec<IdnResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct IdnResult {
    pub domain: String,
    pub mappings: Vec<PunyMapping>,
    pub is_registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PunyMapping {
    pub unicode: String,
    pub ascii: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum LookupResponse {
    Ascii(AsciiResponse),
    Idn(IdnResponse),
}

pub fn empty_ascii_response(domain: &str) -> AsciiResponse {
    AsciiResponse {
        q: domain.to_string(),
        ascii: true,
        puny: false,
        results: Vec::new(),
    }
}

pub fn normalize_domain_input(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut host = if trimmed.contains("://") {
        if let Ok(url) = Url::parse(trimmed) {
            url.host_str().unwrap_or(trimmed).to_string()
        } else {
            trimmed.split("://").nth(1).unwrap_or(trimmed).to_string()
        }
    } else {
        trimmed.to_string()
    };

    if let Some(idx) = host.find(['/', '?', '#']) {
        host.truncate(idx);
    }

    if let Some(idx) = host.rfind(':') {
        let (left, right) = host.split_at(idx);
        if right[1..].chars().all(|c| c.is_ascii_digit()) {
            host = left.to_string();
        }
    }

    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_input_strips_scheme_path_and_subdomains() {
        let cases = [
            ("https://gooble.com", "gooble.com"),
            ("http://gooble.com", "gooble.com"),
            ("ftp://gooble.com", "gooble.com"),
            ("https://foo.gooble.com", "gooble.com"),
            ("http://foo.gooble.com", "gooble.com"),
            ("ftp://foo.gooble.com", "gooble.com"),
            ("foo.gooble.com", "gooble.com"),
            ("gooble.com", "gooble.com"),
            ("gooble.com:8080", "gooble.com"),
            ("gooble.com:8080/foo", "gooble.com"),
            ("http://gooble.com:8080/foo", "gooble.com"),
            ("https://foo.gooble.com:8443/path?x=1#frag", "gooble.com"),
            ("foo.bar.gooble.com", "gooble.com"),
            ("http://foo.bar.gooble.com/path", "gooble.com"),
            ("https://sub.example.com/path", "example.com"),
            ("ftp://a.b.c", "b.c"),
            ("example.com/path", "example.com"),
        ];

        for (input, expected) in cases {
            assert_eq!(normalize_domain_input(input), expected, "input={input}");
        }
    }
}

fn validate<T: Serialize + DeserializeOwned>(value: &T) -> Result<()> {
    let json = serde_json::to_value(value)?;
    let _: T = serde_json::from_value(json)?;
    Ok(())
}

pub fn validate_ascii_response(value: &AsciiResponse) -> Result<()> {
    validate(value)
}

pub fn validate_idn_response(value: &IdnResponse) -> Result<()> {
    validate(value)
}

pub fn validate_lookup_response(value: &LookupResponse) -> Result<()> {
    validate(value)
}
