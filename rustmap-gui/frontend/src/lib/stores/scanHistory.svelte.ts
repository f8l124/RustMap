import type { ScanHistoryEntry } from "../types";

class ScanHistoryStore {
  entries = $state<ScanHistoryEntry[]>([]);

  set(entries: ScanHistoryEntry[]) {
    this.entries = entries;
  }

  get latest(): ScanHistoryEntry | null {
    return this.entries.length > 0 ? this.entries[this.entries.length - 1]! : null;
  }

  getById(scanId: string): ScanHistoryEntry | undefined {
    return this.entries.find((e) => e.scan_id === scanId);
  }
}

export const scanHistory = new ScanHistoryStore();
