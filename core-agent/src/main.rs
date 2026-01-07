use axum::{routing::{get, post}, Router, Json};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::{CorsLayer, Any};

mod watcher;
mod ml_integration;
mod backend_client;
mod config;  // NEW: Add config module

use watcher::{FileWatcher, FileEvent};

struct AppState {
    watcher: Arc<Mutex<FileWatcher>>,
}

#[tokio::main]
async fn main() {
    println!("🚀 CyberGuardian Core Agent starting...");

    let state = Arc::new(AppState {
        watcher: Arc::new(Mutex::new(FileWatcher::new())),
    });

    let app = Router::new()
    .route("/health", get(health_check))
    .route("/status", get(get_status))
    .route("/start-monitoring", post(start_monitoring))
    .route("/stop-monitoring", post(stop_monitoring))
    .route("/events", get(get_events))
    .layer(CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any))
    .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    
    println!("✅ API listening on http://127.0.0.1:3000");

    axum::serve(listener, app)
        .await
        .unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}

#[derive(Serialize)]
struct StatusResponse {
    monitoring: bool,
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct StartMonitoringRequest {
    paths: Vec<String>,
}

async fn get_status(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>
) -> Json<StatusResponse> {
    let watcher = state.watcher.lock().unwrap();
    Json(StatusResponse {
        monitoring: watcher.is_monitoring(),
        paths: watcher.get_paths(),
    })
}

async fn start_monitoring(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<StartMonitoringRequest>
) -> Json<StatusResponse> {
    println!("🟢 Starting monitoring for {} paths", req.paths.len());
    
    let mut watcher = state.watcher.lock().unwrap();
    if let Err(e) = watcher.start(req.paths.clone()) {
        println!("❌ Failed to start watcher: {:?}", e);
    }
    
    Json(StatusResponse {
        monitoring: true,
        paths: req.paths,
    })
}

async fn stop_monitoring(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>
) -> Json<StatusResponse> {
    println!("🔴 Stopping monitoring");
    
    let mut watcher = state.watcher.lock().unwrap();
    watcher.stop();
    
    Json(StatusResponse {
        monitoring: false,
        paths: vec![],
    })
}

async fn get_events(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>
) -> Json<Vec<FileEvent>> {
    let watcher = state.watcher.lock().unwrap();
    Json(watcher.get_events())
}