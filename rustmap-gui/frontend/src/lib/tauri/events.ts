import { listen } from "@tauri-apps/api/event";
import type {
  ScanStartedPayload,
  HostResultPayload,
  ScanCompletePayload,
  ScanErrorPayload,
} from "../types";
import { scanState } from "../stores/scanState.svelte";
import { scanHistory } from "../stores/scanHistory.svelte";
import { getScanHistory } from "./commands";

type UnlistenFn = () => void;

export function setupEventListeners(): () => void {
  const unlisteners: Promise<UnlistenFn>[] = [];

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
      // Refresh history from backend
      getScanHistory().then((entries) => {
        scanHistory.set(entries);
      });
    }),
  );

  unlisteners.push(
    listen<ScanErrorPayload>("scan-error", (event) => {
      scanState.onScanError(event.payload.error);
    }),
  );

  return () => {
    for (const p of unlisteners) {
      p.then((unlisten) => unlisten());
    }
  };
}
