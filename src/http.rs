use anyhow::Result;
use axum::{
	extract::State,
	http::StatusCode,
	response::{IntoResponse, Response},
	routing::{get, post},
	Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::ascii_spoof;
use crate::idn;

#[derive(Clone)]
struct AppState {
	db_path: String,
}

#[derive(Deserialize)]
struct LookupRequest {
	domain: String,
}

pub async fn serve(host: String, port: u16, db_path: String) -> Result<()> {
	let state = AppState { db_path };
	let app = Router::new()
		.route("/healthz", get(healthz))
		.route("/lookup", post(lookup))
		.route("/ascii", post(ascii))
		.route("/idn", post(idn_lookup))
		.with_state(state);

	let addr: SocketAddr = format!("{host}:{port}").parse()?;
	println!("Listening on http://{addr}");
	axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
	Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
	Json(json!({ "ok": true }))
}

async fn lookup(State(state): State<AppState>, Json(payload): Json<LookupRequest>) -> Response {
	let domain = payload.domain;
	let is_idn = domain.starts_with("xn--") || domain.chars().any(|c| c as u32 > 127);
	if is_idn {
		idn_lookup(State(state), Json(LookupRequest { domain })).await
	} else {
		ascii(State(state), Json(LookupRequest { domain })).await
	}
}

async fn ascii(State(state): State<AppState>, Json(payload): Json<LookupRequest>) -> Response {
	let db_path = state.db_path.clone();
	let domain = payload.domain.clone();
	let result = tokio::task::spawn_blocking(move || ascii_spoof::lookup_ascii(&domain, &db_path))
		.await;

	match result {
		Ok(Ok(json)) => (StatusCode::OK, Json(json)).into_response(),
		Ok(Err(err)) => server_error(err),
		Err(err) => server_error(err),
	}
}

async fn idn_lookup(State(_state): State<AppState>, Json(payload): Json<LookupRequest>) -> Response {
	let domain = payload.domain.clone();
	let result = tokio::task::spawn_blocking(move || idn::lookup_idn(&domain)).await;

	match result {
		Ok(Ok(json)) => (StatusCode::OK, Json(json)).into_response(),
		Ok(Err(err)) => server_error(err),
		Err(err) => server_error(err),
	}
}

fn server_error<E: std::fmt::Display>(err: E) -> Response {
	let body = json!({ "error": err.to_string() });
	(StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}
