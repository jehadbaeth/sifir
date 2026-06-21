use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub prompt: String,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    pub text: String,
    pub tokens_used: u32,
}

/// Forward a /v1/generate request to the inference backend.
///
/// When `backend_url` is None (--no-backend mode), returns an echo response
/// so Phase 1 can be tested without the 3070 or any inference server running.
pub async fn handle_generate(
    headers: HeaderMap,
    body: Bytes,
    backend_url: Option<String>,
) -> impl IntoResponse {
    let Some(url) = backend_url else {
        return echo_response(body);
    };

    let client = reqwest::Client::new();
    let target = format!("{url}/v1/generate");

    let mut req = client.post(&target).body(body.to_vec());
    if let Some(ct) = headers.get("content-type") {
        req = req.header("content-type", ct);
    }

    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.bytes().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => {
            eprintln!("[proxy] backend error: {e}");
            (StatusCode::BAD_GATEWAY, format!("backend unavailable: {e}")).into_response()
        }
    }
}

fn echo_response(body: Bytes) -> axum::response::Response {
    let prompt = serde_json::from_slice::<GenerateRequest>(&body)
        .map(|r| r.prompt)
        .unwrap_or_else(|_| "(unparseable request)".to_string());

    let resp = GenerateResponse {
        text: format!("[mock inference] echo: {prompt}"),
        tokens_used: 0,
    };

    axum::Json(resp).into_response()
}
