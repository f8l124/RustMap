import type {
  HostScanResult,
  ScanResult,
  HostResultPayload,
} from "../types";

export type ScanPhase =
  | "idle"
  | "starting"
  | "scanning"
  | "complete"
  | "error";

export type ErrorKind = "config" | "scan" | "privilege" | "backend" | null;

class ScanStateStore {
  phase = $state<ScanPhase>("idle");
  scanId = $state<string | null>(null);
  hostResults = $state<HostScanResult[]>([]);
  hostsCompleted = $state(0);
  hostsTotal = $state(0);
  finalResult = $state<ScanResult | null>(null);
  error = $state<string | null>(null);
  errorKind = $state<ErrorKind>(null);
  startedAt = $state<number | null>(null);

  get isScanning(): boolean {
    return this.phase === "starting" || this.phase === "scanning";
  }

  get progressPercent(): number {
    if (this.hostsTotal === 0) return 0;
    return Math.round((this.hostsCompleted / this.hostsTotal) * 100);
  }

  get openPortCount(): number {
    let count = 0;
    for (const host of this.hostResults) {
      for (const port of host.ports) {
        if (port.state === "open") count++;
      }
    }
    return count;
  }

  get hostsUp(): number {
    return this.hostResults.filter((h) => h.host_status === "Up").length;
  }

  onStarting() {
    this.phase = "starting";
    this.hostResults = [];
    this.hostsCompleted = 0;
    this.hostsTotal = 0;
    this.finalResult = null;
    this.error = null;
    this.errorKind = null;
    this.startedAt = Date.now();
  }

  onScanStarted(scanId: string, hostsTotal: number) {
    this.phase = "scanning";
    this.scanId = scanId;
    this.hostsTotal = hostsTotal;
  }

  onHostResult(payload: HostResultPayload) {
    this.hostResults.push(payload.result);
    // Trigger Svelte 5 reactivity by reassigning the reference.
    this.hostResults = this.hostResults;
    this.hostsCompleted = payload.hosts_completed;
    this.hostsTotal = payload.hosts_total;
  }

  onScanComplete(result: ScanResult) {
    this.phase = "complete";
    this.finalResult = result;
    this.hostsCompleted = result.hosts.length;
    this.hostsTotal = result.hosts.length;
  }

  onScanError(error: string, kind: ErrorKind = "scan") {
    // Don't change phase to "error" if a scan is still in progress — show
    // the error banner without interrupting result streaming.
    if (this.phase !== "starting" && this.phase !== "scanning") {
      this.phase = "error";
    }
    this.error = error;
    this.errorKind = kind;
  }

  dismissError() {
    this.error = null;
    this.errorKind = null;
    if (this.phase === "error") {
      this.phase = this.hostResults.length > 0 ? "complete" : "idle";
    }
  }

  reset() {
    this.phase = "idle";
    this.scanId = null;
    this.hostResults = [];
    this.hostsCompleted = 0;
    this.hostsTotal = 0;
    this.finalResult = null;
    this.error = null;
    this.errorKind = null;
    this.startedAt = null;
  }
}

export const scanState = new ScanStateStore();
