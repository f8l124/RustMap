import type { CheckpointInfo, ScanHistoryEntry } from "../types";
import { clearScanHistory, listCheckpoints } from "../tauri/commands";

class ScanHistoryStore {
  entries = $state<ScanHistoryEntry[]>([]);
  checkpoints = $state<CheckpointInfo[]>([]);

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
    return this.entries.length > 0 ? this.entries[0]! : null;
  }

  getById(scanId: string): ScanHistoryEntry | undefined {
    return this.entries.find((e) => e.scan_id === scanId);
  }

  hasCheckpoint(scanId: string): boolean {
    return this.checkpoints.some((cp) => cp.scan_id === scanId);
  }

  getCheckpoint(scanId: string): CheckpointInfo | undefined {
    return this.checkpoints.find((cp) => cp.scan_id === scanId);
  }

  async loadCheckpoints(): Promise<void> {
    try {
      this.checkpoints = await listCheckpoints();
    } catch (err) {
      console.error("Failed to load checkpoints:", err);
    }
  }

  removeCheckpoint(scanId: string) {
    this.checkpoints = this.checkpoints.filter((cp) => cp.scan_id !== scanId);
  }
}

export const scanHistory = new ScanHistoryStore();
