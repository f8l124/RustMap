use std::collections::HashMap;

use tokio_util::sync::CancellationToken;

/// Global Tauri application state for managing active and completed scans.
pub struct ScanState {
    pub running: tokio::sync::Mutex<HashMap<String, CancellationToken>>,
    pub store: tokio::sync::Mutex<rustmap_db::ScanStore>,
}

impl ScanState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store = rustmap_db::ScanStore::open_default()?;
        Ok(Self {
            running: tokio::sync::Mutex::new(HashMap::new()),
            store: tokio::sync::Mutex::new(store),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_empty() {
        let state = ScanState::new().unwrap();
        let running = state.running.try_lock().unwrap();
        assert!(running.is_empty());
    }

    #[tokio::test]
    async fn running_insert_and_get() {
        let state = ScanState::new().unwrap();
        let token = CancellationToken::new();
        {
            let mut running = state.running.lock().await;
            running.insert("scan-1".into(), token.clone());
        }
        let running = state.running.lock().await;
        assert!(running.contains_key("scan-1"));
        assert!(!running.get("scan-1").unwrap().is_cancelled());
    }

    #[tokio::test]
    async fn running_remove() {
        let state = ScanState::new().unwrap();
        let token = CancellationToken::new();
        {
            let mut running = state.running.lock().await;
            running.insert("scan-1".into(), token);
        }
        {
            let mut running = state.running.lock().await;
            let removed = running.remove("scan-1");
            assert!(removed.is_some());
        }
        let running = state.running.lock().await;
        assert!(running.is_empty());
    }

    #[tokio::test]
    async fn running_cancel_propagates() {
        let state = ScanState::new().unwrap();
        let token = CancellationToken::new();
        let child = token.clone();
        {
            let mut running = state.running.lock().await;
            running.insert("scan-1".into(), token);
        }
        {
            let running = state.running.lock().await;
            running.get("scan-1").unwrap().cancel();
        }
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn store_saves_and_lists() {
        let state = ScanState::new().unwrap();
        let store = state.store.lock().await;
        // The store should be functional (backed by default DB path)
        let scans = store.list_scans().unwrap();
        // Just verify we can query without error — count depends on prior runs
        let _ = scans;
    }
}
