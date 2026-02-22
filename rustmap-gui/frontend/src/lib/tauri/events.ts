import { listen } from "@tauri-apps/api/event";
import type {
  ScanStartedPayload,
  HostResultPayload,
  ScanCompletePayload,
  ScanErrorPayload,
  ScanLogPayload,
} from "../types";
import { scanState } from "../stores/scanState.svelte";
import { scanHistory } from "../stores/scanHistory.svelte";
import { getScanHistory } from "./commands";

type UnlistenFn = () => void;

function refreshHistory() {
  getScanHistory()
    .then((entries) => {
      scanHistory.set(entries);
    })
    .catch((err) => {
      console.error("Failed to load scan history:", err);
    });
}

export function setupEventListeners(): () => void {
  const unlisteners: Promise<UnlistenFn>[] = [];

  // Load history from DB on startup
  refreshHistory();

  unlisteners.push(
    listen<ScanStartedPayload>("scan-started", (event) => {
      scanState.onScanStarted(event.payload.scan_id, event.payload.hosts_total);
    }),
  );

  unlisteners.push(
    listen<HostResultPayload>("host-result", (event) => {
      scanState.onHostResult(event.payload);
    }),
  );

  unlisteners.push(
    listen<ScanCompletePayload>("scan-complete", (event) => {
      scanState.onScanComplete(event.payload.result);
      refreshHistory();
    }),
  );

  unlisteners.push(
    listen<ScanErrorPayload>("scan-error", (event) => {
      scanState.onScanError(event.payload.error);
      refreshHistory();
    }),
  );

  unlisteners.push(
    listen<ScanLogPayload>("scan-log", (event) => {
      scanState.onScanLog(event.payload.message);
    }),
  );

  return () => {
    for (const p of unlisteners) {
      p.then((unlisten) => unlisten());
    }
  };
}
