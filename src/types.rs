use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
