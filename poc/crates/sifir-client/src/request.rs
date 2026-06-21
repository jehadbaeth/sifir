use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct GenerateRequest<'a> {
    pub prompt: &'a str,
    pub max_tokens: u32,
}

#[derive(Deserialize, Debug)]
pub struct GenerateResponse {
    pub text: String,
    pub tokens_used: u32,
}

/// Send a /v1/generate request to the server and return the response.
pub async fn generate(
    client: &reqwest::Client,
    base_url: &str,
    prompt: &str,
    max_tokens: u32,
) -> anyhow::Result<GenerateResponse> {
    let url = format!("{base_url}/v1/generate");
    let resp = client
        .post(&url)
        .json(&GenerateRequest { prompt, max_tokens })
        .send()
        .await?
        .error_for_status()?
        .json::<GenerateResponse>()
        .await?;
    Ok(resp)
}
