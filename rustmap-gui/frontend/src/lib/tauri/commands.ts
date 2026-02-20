import { invoke } from "@tauri-apps/api/core";
import type { GuiScanConfig, PrivilegeInfo, ScanHistoryEntry } from "../types";

export async function startScan(config: GuiScanConfig): Promise<string> {
  return invoke<string>("start_scan", { config });
}

export async function stopScan(scanId: string): Promise<void> {
  return invoke<void>("stop_scan", { scanId });
}

export async function getScanHistory(): Promise<ScanHistoryEntry[]> {
  return invoke<ScanHistoryEntry[]>("get_scan_history");
}

export async function exportResults(
  scanId: string,
  format: string,
): Promise<string> {
  return invoke<string>("export_results", { scanId, format });
}

export async function checkPrivileges(): Promise<PrivilegeInfo> {
  return invoke<PrivilegeInfo>("check_privileges_cmd");
}
