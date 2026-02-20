// ---------------------------------------------------------------------------
// WebSocket event streaming
// ---------------------------------------------------------------------------

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::response::Response;
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;

use crate::error::ApiError;
use crate::state::{AppState, ScanStatus, WsEvent};

/// Maximum number of concurrent WebSocket connections.
const MAX_WS_CONNECTIONS: usize = 100;

/// RAII guard that decrements the WebSocket connection counter on drop.
struct WsConnectionGuard {
    state: Arc<AppState>,
}

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        self.state.ws_connection_count.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

pub async fn scan_events_ws(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Verify token for WebSocket (browsers can't set Authorization headers).
    //
    // SECURITY NOTE: Passing the auth token as a URL query parameter is a
    // known limitation of the WebSocket protocol (browsers cannot set custom
    // headers on WebSocket upgrade requests). This means the token may appear
    // in server access logs, browser history, and proxy logs. A more secure
    // approach would be ticket-based authentication where the client first
    // obtains a short-lived, single-use ticket via an authenticated REST
    // endpoint and then passes that ticket in the WebSocket URL.
    // TODO: Implement ticket-based auth for WebSocket connections to avoid
    //       exposing the long-lived API key in URLs.
    if let Some(ref expected_hash) = state.api_key_hash {
        use sha2::{Digest, Sha256};
        let provided = params.token.as_deref().unwrap_or("");
        let provided_hash = Sha256::digest(provided.as_bytes());
        if !bool::from(expected_hash.ct_eq(provided_hash.as_slice())) {
            return Err(ApiError::Unauthorized(
                "valid token query parameter required for WebSocket".into(),
            ));
        }
    }

    // Look up the scan
    let scans = state.scans.read().await;
    let tracked = scans.get(&scan_id).ok_or_else(|| {
        ApiError::NotFound(format!("scan not found: {scan_id}"))
    })?;

    // Subscribe to the broadcast channel
    let event_rx = tracked.event_tx.subscribe();
    let status = tracked.status.clone();
    drop(scans);

    // If scan already completed, return an error
    if matches!(
        status,
        ScanStatus::Completed | ScanStatus::Cancelled | ScanStatus::Error(_)
    ) {
        return Err(ApiError::Conflict(
            "scan already completed; use GET /api/scans/{id} for results".into(),
        ));
    }

    // Enforce WebSocket connection limit
    let prev = state.ws_connection_count.fetch_add(1, Ordering::Relaxed);
    if prev >= MAX_WS_CONNECTIONS {
        state.ws_connection_count.fetch_sub(1, Ordering::Relaxed);
        return Err(ApiError::Conflict(
            "too many WebSocket connections; try again later".into(),
        ));
    }
    let guard = WsConnectionGuard { state: state.clone() };

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, event_rx, guard)))
}

async fn handle_ws(
    mut socket: WebSocket,
    mut event_rx: broadcast::Receiver<Arc<WsEvent>>,
    _guard: WsConnectionGuard,
) {
    loop {
        match event_rx.recv().await {
            Ok(event) => {
                let is_terminal = matches!(
                    event.as_ref(),
                    WsEvent::Complete { .. } | WsEvent::Error { .. }
                );

                let json =
                    serde_json::to_string(event.as_ref()).unwrap_or_default();

                if socket.send(Message::Text(json.into())).await.is_err() {
                    // Client disconnected
                    break;
                }

                if is_terminal {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let warning = serde_json::json!({
                    "type": "warning",
                    "message": format!("missed {n} events due to slow consumption")
                });
                let msg = Message::Text(warning.to_string().into());
                if socket.send(msg).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}
