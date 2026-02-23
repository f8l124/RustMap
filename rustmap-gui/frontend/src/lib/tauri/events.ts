import { listen } from "@tauri-apps/api/event";
import type {
  ScanStartedPayload,
  HostResultPayload,
  ScanCompletePayload,
  ScanErrorPayload,
  ScanLogPayload,
  WatchIterationPayload,
} from "../types";
import { scanState } from "../stores/scanState.svelte";
import { scanHistory } from "../stores/scanHistory.svelte";
import { toasts } from "../stores/toast.svelte";
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
  scanHistory.loadCheckpoints();
}

export function setupEventListeners(): () => void {
  const unlisteners: Promise<UnlistenFn>[] = [];

  // Host result batching for large scans — accumulates events and flushes
  // in a single reactivity update every 50 results or 100ms.
  let hostResultBuffer: HostResultPayload[] = [];
  let batchTimeout: ReturnType<typeof setTimeout> | null = null;

  function flushHostResults() {
    if (hostResultBuffer.length === 0) return;
    scanState.onHostResultBatch(hostResultBuffer);
    hostResultBuffer = [];
    batchTimeout = null;
  }

  // Load history from DB on startup
  refreshHistory();

  unlisteners.push(
    listen<ScanStartedPayload>("scan-started", (event) => {
      scanState.onScanStarted(event.payload.scan_id, event.payload.hosts_total);
    }),
  );

  unlisteners.push(
    listen<HostResultPayload>("host-result", (event) => {
      hostResultBuffer.push(event.payload);
      if (hostResultBuffer.length >= 50) {
        if (batchTimeout) {
          clearTimeout(batchTimeout);
          batchTimeout = null;
        }
        flushHostResults();
      } else if (!batchTimeout) {
        batchTimeout = setTimeout(flushHostResults, 100);
      }
    }),
  );

  unlisteners.push(
    listen<ScanCompletePayload>("scan-complete", (event) => {
      // Flush any buffered host results before completing
      flushHostResults();
      scanState.onScanComplete(event.payload.result);
      refreshHistory();
      const hostCount = event.payload.result.hosts.length;
      const openPorts = event.payload.result.hosts.reduce(
        (sum, h) => sum + h.ports.filter((p) => p.state === "open").length,
        0,
      );
      toasts.success(`Scan complete: ${hostCount} host(s), ${openPorts} open port(s)`);
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

  unlisteners.push(
    listen<WatchIterationPayload>("watch-iteration", (event) => {
      const { iteration, diff } = event.payload;
      refreshHistory();
      if (diff) {
        const changes =
          diff.new_hosts.length + diff.removed_hosts.length + diff.port_changes.length;
        if (changes > 0) {
          toasts.warn(`Watch #${iteration}: ${changes} change(s) detected`);
        } else {
          toasts.info(`Watch #${iteration}: no changes`);
        }
      } else {
        toasts.info(`Watch #${iteration}: baseline scan complete`);
      }
    }),
  );

  return () => {
    // Clear any pending batch flush to avoid stale updates after teardown
    if (batchTimeout) {
      clearTimeout(batchTimeout);
      batchTimeout = null;
    }
    for (const p of unlisteners) {
      p.then((unlisten) => unlisten()).catch(() => {});
    }
  };
}
