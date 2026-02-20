// ---------------------------------------------------------------------------
// REST API server
// ---------------------------------------------------------------------------
//
// Exposes RustMap scanning capabilities via HTTP/WebSocket endpoints.

pub mod auth;
pub mod config;
pub mod error;
mod routes;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use state::AppState;

/// Configuration for the API server.
pub struct ApiConfig {
    pub listen_addr: SocketAddr,
    pub api_key: Option<String>,
}

/// Build the axum Router (useful for testing).
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    routes::build_router(state)
}

/// Start the API server and block until shutdown (Ctrl+C).
pub async fn start_server(config: ApiConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(config.api_key));

    // Seed bundled CVEs for vuln endpoints
    {
        let store = state.store.lock().await;
        rustmap_vuln::seed_bundled_cves(&store).ok();
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("API server shut down");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received");
}
