// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

mod diff;
mod scans;
mod system;
mod vuln;
mod ws;

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

use crate::auth::auth_middleware;
use crate::state::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    // Launch a single background task that sweeps completed scans from memory.
    scans::spawn_scan_sweep_task(state.clone());

    let health_route = Router::new().route("/api/system/health", get(system::health_check));

    let api_routes = Router::new()
        .route("/api/scans", post(scans::start_scan).get(scans::list_scans))
        .route(
            "/api/scans/{id}",
            get(scans::get_scan).delete(scans::delete_scan),
        )
        .route("/api/scans/{id}/stop", post(scans::stop_scan))
        .route("/api/scans/{id}/export", get(scans::export_scan))
        .route("/api/scans/{id}/diff/{other_id}", get(diff::diff_scans))
        .route("/api/scans/{id}/events", get(ws::scan_events_ws))
        .route("/api/vuln/check", post(vuln::vuln_check))
        .route("/api/vuln/update", post(vuln::vuln_update))
        .route("/api/system/privileges", get(system::get_privileges));

    // Apply auth middleware only if api_key_hash is configured
    let api_routes = if state.api_key_hash.is_some() {
        api_routes.layer(from_fn_with_state(state.clone(), auth_middleware))
    } else {
        api_routes
    };

    // CORS: restrict to localhost origins by default. When the API is bound to
    // 127.0.0.1 this is the expected usage; if exposed to a network, the user
    // should place it behind a reverse proxy that handles CORS properly.
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:1420".parse().unwrap(), // Tauri dev server
            "http://localhost:5173".parse().unwrap(), // Vite dev server
            "tauri://localhost".parse().unwrap(),     // Tauri production
            "https://tauri.localhost".parse().unwrap(), // Tauri production (alt)
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .max_age(std::time::Duration::from_secs(3600));

    health_route
        .merge(api_routes)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2 MB (scan configs are small)
        .with_state(state)
}
