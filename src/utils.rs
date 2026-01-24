use base64::{encode, decode};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use serde_json::json;
use std::env;
use std::sync::Mutex;
use ttl_cache::TtlCache;
use std::time::Duration;
use std::collections::HashMap;

pub fn encrypt_base64(string: &str) -> String {
    encode(string)
}

pub fn decrypt_base64(encoded_string: &str) -> String {
    let decoded_bytes = decode(encoded_string).unwrap();
    String::from_utf8(decoded_bytes).unwrap()
}

pub fn create_oauth2_session() -> BasicClient {
    dotenv::dotenv().ok();
    let client_id = env::var("OAUTH2_CLIENT_ID").expect("OAUTH2_CLIENT_ID not set");
    let client_secret = env::var("OAUTH2_CLIENT_SECRET").expect("OAUTH2_CLIENT_SECRET not set");
    let redirect_uri = env::var("OAUTH2_REDIRECT_URI").expect("OAUTH2_REDIRECT_URI not set");

    BasicClient::new(
        client_id,
        Some(client_secret),
        AuthorizationCode::new("https://discordapp.com/api/v9/oauth2/authorize".to_string()),
        Some(TokenResponse::new("https://discordapp.com/api/v9/oauth2/token".to_string())),
    )
    .set_redirect_uri(redirect_uri)
}

pub fn update_token_in_session(token: &str, session: &mut TtlCache<String, String>) {
    session.insert("oauth2_token".to_string(), token.to_string());
}
