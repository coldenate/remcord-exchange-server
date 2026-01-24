use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::middleware::Logger;
use actix_web::http::header;
use actix_web::web::Json;
use actix_cors::Cors;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Mutex;
use ttl_cache::TtlCache;
use std::time::Duration;
use std::collections::HashMap;
use std::env;

#[derive(Serialize, Deserialize)]
struct Activity {
    r#type: i32,
    application_id: i32,
    name: String,
    details: String,
    state: String,
    assets: Option<HashMap<String, String>>,
    platform: String,
}

#[derive(Serialize, Deserialize)]
struct UserToken {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
    scope: Vec<String>,
    token_type: String,
    expires_at: f64,
}

#[derive(Serialize, Deserialize)]
struct Interaction {
    token: UserToken,
    activity: Option<Activity>,
    session_id: Option<String>,
}

struct AppState {
    sessions: Mutex<TtlCache<String, String>>,
}

async fn callback(session: Session, query: web::Query<HashMap<String, String>>, data: web::Data<AppState>) -> impl Responder {
    if let Some(error) = query.get("error") {
        return HttpResponse::BadRequest().body(error.clone());
    }

    let client = create_oauth2_client();
    let token = client.exchange_code(AuthorizationCode::new(query.get("code").unwrap().clone()))
        .request_async(async_http_client).await.unwrap();

    let token_json = json!(token);
    session.insert("oauth2_token", &token_json).unwrap();

    let encrypted_token = base64::encode(token_json.to_string());
    HttpResponse::Ok().body(encrypted_token)
}

async fn refresh(session: Session, interaction: Json<Interaction>, data: web::Data<AppState>) -> impl Responder {
    if let Some(error) = session.get::<String>("error").unwrap() {
        return HttpResponse::BadRequest().body(error);
    }

    let client = create_oauth2_client();
    let token = client.exchange_refresh_token(&interaction.token.refresh_token)
        .request_async(async_http_client).await.unwrap();

    session.insert("oauth2_token", &token).unwrap();
    HttpResponse::Ok().json(token)
}

async fn create_activity(interaction: Json<Interaction>, data: web::Data<AppState>) -> impl Responder {
    let client = create_oauth2_client();
    let token = client.exchange_refresh_token(&interaction.token.refresh_token)
        .request_async(async_http_client).await.unwrap();

    let activities = vec![json!({
        "type": interaction.activity.as_ref().unwrap().r#type,
        "application_id": interaction.activity.as_ref().unwrap().application_id,
        "name": interaction.activity.as_ref().unwrap().name,
        "details": interaction.activity.as_ref().unwrap().details,
        "state": interaction.activity.as_ref().unwrap().state,
        "assets": interaction.activity.as_ref().unwrap().assets,
        "platform": interaction.activity.as_ref().unwrap().platform,
    })];

    let response = client.post("https://discordapp.com/api/v9/users/@me/headless-sessions")
        .bearer_auth(&token.access_token().secret())
        .json(&json!({ "activities": activities }))
        .send().await.unwrap();

    if response.status().is_success() {
        let session_token = response.json::<HashMap<String, String>>().await.unwrap().get("token").unwrap().clone();
        HttpResponse::Ok().body(session_token)
    } else {
        HttpResponse::InternalServerError().body("Failed to create activity")
    }
}

async fn delete_session(interaction: Json<Interaction>, data: web::Data<AppState>) -> impl Responder {
    if interaction.session_id.is_none() {
        return HttpResponse::NotFound().finish();
    }

    let client = create_oauth2_client();
    let token = client.exchange_refresh_token(&interaction.token.refresh_token)
        .request_async(async_http_client).await.unwrap();

    let response = client.post("https://discordapp.com/api/v9/users/@me/headless-sessions/delete")
        .bearer_auth(&token.access_token().secret())
        .json(&json!({ "token": interaction.session_id.as_ref().unwrap() }))
        .send().await.unwrap();

    if response.status().is_success() {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::InternalServerError().body("Failed to delete session")
    }
}

async fn edit_session(interaction: Json<Interaction>, data: web::Data<AppState>) -> impl Responder {
    if interaction.session_id.is_none() {
        return HttpResponse::NotFound().finish();
    }

    let client = create_oauth2_client();
    let token = client.exchange_refresh_token(&interaction.token.refresh_token)
        .request_async(async_http_client).await.unwrap();

    let response = client.post("https://discordapp.com/api/v9/users/@me/headless-sessions")
        .bearer_auth(&token.access_token().secret())
        .json(&json!({
            "activities": [json!(interaction.activity.as_ref().unwrap())],
            "token": interaction.session_id.as_ref().unwrap()
        }))
        .send().await.unwrap();

    if response.status().is_success() {
        HttpResponse::Ok().body(interaction.session_id.as_ref().unwrap().clone())
    } else {
        HttpResponse::InternalServerError().body("Failed to edit session")
    }
}

async fn heartbeat(session: Session, interaction: Json<Interaction>, data: web::Data<AppState>) -> impl Responder {
    let client_id = session.get::<String>("client_id").unwrap_or_else(|_| None);

    if client_id.is_none() {
        return HttpResponse::BadRequest().body("No client found.");
    }

    let client_id = client_id.unwrap();
    let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let mut sessions = data.sessions.lock().unwrap();
    sessions.insert(client_id.clone(), current_time.to_string());

    tokio::spawn(mourn_loss(interaction.into_inner(), client_id.clone(), data.clone()));

    HttpResponse::Ok().json(json!({ "message": "Heartbeat received." }))
}

async fn mourn_loss(interaction: Interaction, client_id: String, data: web::Data<AppState>) {
    let mut seconds_passed = 0;
    let mut sessions = data.sessions.lock().unwrap();

    while sessions.contains_key(&client_id) {
        if seconds_passed > 15 {
            break;
        }
        drop(sessions);
        tokio::time::sleep(Duration::from_secs(1)).await;
        seconds_passed += 1;
        sessions = data.sessions.lock().unwrap();
    }

    if !sessions.contains_key(&client_id) {
        delete_session(Json(interaction), data).await;
    }
}

fn create_oauth2_client() -> BasicClient {
    dotenv().ok();
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let app_state = web::Data::new(AppState {
        sessions: Mutex::new(TtlCache::new(Duration::from_secs(15))),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                env::var("SESSION_SECRET_KEY").expect("SESSION_SECRET_KEY not set").into_bytes(),
            ))
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600),
            )
            .route("/callback", web::get().to(callback))
            .route("/refresh", web::post().to(refresh))
            .route("/create", web::post().to(create_activity))
            .route("/delete", web::post().to(delete_session))
            .route("/edit", web::post().to(edit_session))
            .route("/heartbeat", web::post().to(heartbeat))
    })
    .bind(("0.0.0.0", 5032))?
    .run()
    .await
}
