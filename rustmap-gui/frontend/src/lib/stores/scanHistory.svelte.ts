import type { ScanHistoryEntry } from "../types";
import { clearScanHistory } from "../tauri/commands";

class ScanHistoryStore {
  entries = $state<ScanHistoryEntry[]>([]);

  set(entries: ScanHistoryEntry[]) {
    this.entries = entries;
  }

  addEntry(entry: ScanHistoryEntry) {
    this.entries = [entry, ...this.entries];
  }

  async clear(): Promise<boolean> {
    try {
      await clearScanHistory();
      this.entries = [];
      return true;
    } catch (err) {
      console.error("Failed to clear scan history:", err);
      return false;
    }
  }

  get latest(): ScanHistoryEntry | null {
    return this.entries.length > 0 ? this.entries[this.entries.length - 1]! : null;
  }

  getById(scanId: string): ScanHistoryEntry | undefined {
    return this.entries.find((e) => e.scan_id === scanId);
  }
}

export const scanHistory = new ScanHistoryStore();
