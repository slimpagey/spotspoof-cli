/*
HTTP API server for SpotSpoof. Exposes lookup endpoints, a health check,
and OpenAPI/Swagger docs for integration with SOAR and automation systems.
*/
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::ascii_spoof;
use crate::idn;
use crate::types::{AsciiResponse, HealthzResponse, IdnResponse, LookupRequest, LookupResponse};

#[derive(Clone)]
struct AppState {
    db_path: String,
    use_db: bool,
}

#[derive(OpenApi)]
#[openapi(
	paths(healthz, lookup, ascii, idn_lookup),
	components(
		schemas(
			LookupRequest,
			HealthzResponse,
			LookupResponse,
			AsciiResponse,
			IdnResponse,
			crate::types::AsciiResult,
			crate::types::IdnResult,
			crate::types::PunyMapping
		)
	),
	tags(
		(name = "spotspoof", description = "SpotSpoof CLI HTTP API")
	)
)]
struct ApiDoc;

pub async fn serve(host: String, port: u16, db_path: String, use_db: bool) -> Result<()> {
    let state = AppState { db_path, use_db };
    let openapi = ApiDoc::openapi();
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/lookup", post(lookup))
        .route("/ascii", post(ascii))
        .route("/idn", post(idn_lookup))
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", openapi));

    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    println!("Listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn index() -> Html<String> {
    let html = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>SpotSpoof CLI</title>
  </head>
  <body>
    <h1>SpotSpoof CLI</h1>
    <p>Available routes:</p>
    <ul>
      <li>GET /healthz</li>
      <li>POST /lookup</li>
      <li>POST /ascii</li>
      <li>POST /idn</li>
      <li>GET /docs</li>
    </ul>
  </body>
</html>"#;
    Html(html.to_string())
}

#[utoipa::path(
	get,
	path = "/healthz",
	tag = "spotspoof",
	responses((status = 200, body = HealthzResponse))
)]
async fn healthz() -> Json<HealthzResponse> {
    Json(HealthzResponse { ok: true })
}

#[utoipa::path(
	post,
	path = "/lookup",
	tag = "spotspoof",
	request_body = LookupRequest,
	responses((status = 200, body = LookupResponse))
)]
async fn lookup(State(state): State<AppState>, Json(payload): Json<LookupRequest>) -> Response {
    let domain = crate::types::normalize_domain_input(&payload.domain);
    let is_idn = domain.starts_with("xn--") || domain.chars().any(|c| c as u32 > 127);
    if is_idn {
        let response = tokio::task::spawn_blocking(move || idn::lookup_idn(&domain)).await;
        match response {
            Ok(Ok(result)) => {
                let wrapped = LookupResponse::Idn(result);
                if let Err(err) = crate::types::validate_lookup_response(&wrapped) {
                    return server_error(err);
                }
                (StatusCode::OK, Json(wrapped)).into_response()
            }
            Ok(Err(err)) => server_error(err),
            Err(err) => server_error(err),
        }
    } else {
        if !state.use_db {
            let wrapped = LookupResponse::Ascii(crate::types::empty_ascii_response(&domain));
            if let Err(err) = crate::types::validate_lookup_response(&wrapped) {
                return server_error(err);
            }
            return (StatusCode::OK, Json(wrapped)).into_response();
        }

        let db_path = state.db_path.clone();
        let response =
            tokio::task::spawn_blocking(move || ascii_spoof::lookup_ascii(&domain, &db_path)).await;
        match response {
            Ok(Ok(result)) => {
                let wrapped = LookupResponse::Ascii(result);
                if let Err(err) = crate::types::validate_lookup_response(&wrapped) {
                    return server_error(err);
                }
                (StatusCode::OK, Json(wrapped)).into_response()
            }
            Ok(Err(err)) => server_error(err),
            Err(err) => server_error(err),
        }
    }
}

#[utoipa::path(
	post,
	path = "/ascii",
	tag = "spotspoof",
	request_body = LookupRequest,
	responses((status = 200, body = AsciiResponse))
)]
async fn ascii(State(state): State<AppState>, Json(payload): Json<LookupRequest>) -> Response {
    let domain = crate::types::normalize_domain_input(&payload.domain);
    if !state.use_db {
        let response = crate::types::empty_ascii_response(&domain);
        if let Err(err) = crate::types::validate_ascii_response(&response) {
            return server_error(err);
        }
        return (StatusCode::OK, Json(response)).into_response();
    }
    let db_path = state.db_path.clone();
    let result =
        tokio::task::spawn_blocking(move || ascii_spoof::lookup_ascii(&domain, &db_path)).await;

    match result {
        Ok(Ok(response)) => {
            if let Err(err) = crate::types::validate_ascii_response(&response) {
                return server_error(err);
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(Err(err)) => server_error(err),
        Err(err) => server_error(err),
    }
}

#[utoipa::path(
	post,
	path = "/idn",
	tag = "spotspoof",
	request_body = LookupRequest,
	responses((status = 200, body = IdnResponse))
)]
async fn idn_lookup(
    State(_state): State<AppState>,
    Json(payload): Json<LookupRequest>,
) -> Response {
    let domain = crate::types::normalize_domain_input(&payload.domain);
    let result = tokio::task::spawn_blocking(move || idn::lookup_idn(&domain)).await;

    match result {
        Ok(Ok(response)) => {
            if let Err(err) = crate::types::validate_idn_response(&response) {
                return server_error(err);
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(Err(err)) => server_error(err),
        Err(err) => server_error(err),
    }
}

fn server_error<E: std::fmt::Display>(err: E) -> Response {
    let body = json!({ "error": err.to_string() });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let Json(value) = healthz().await;
        assert_eq!(value, HealthzResponse { ok: true });
    }

    #[tokio::test]
    async fn index_lists_routes() {
        let Html(body) = index().await;
        assert!(body.contains("SpotSpoof CLI"));
        assert!(body.contains("GET /healthz"));
        assert!(body.contains("POST /lookup"));
        assert!(body.contains("GET /docs"));
    }

    #[test]
    fn server_error_sets_status() {
        let response = server_error("boom");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
