import { invoke } from "@tauri-apps/api/core";
import type {
  GuiScanConfig,
  PresetInfo,
  PrivilegeInfo,
  ScanHistoryEntry,
  ScriptInfo,
} from "../types";

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

export async function clearScanHistory(): Promise<number> {
  return invoke<number>("clear_scan_history");
}

export async function checkPrivileges(): Promise<PrivilegeInfo> {
  return invoke<PrivilegeInfo>("check_privileges_cmd");
}

export async function listScripts(): Promise<ScriptInfo[]> {
  return invoke<ScriptInfo[]>("list_scripts");
}

export async function getScriptsDir(): Promise<string | null> {
  return invoke<string | null>("get_scripts_dir");
}

export async function parseCustomScripts(
  paths: string[],
): Promise<ScriptInfo[]> {
  return invoke<ScriptInfo[]>("parse_custom_scripts", { paths });
}

export async function exportToFile(
  scanId: string,
  format: string,
  path: string,
): Promise<void> {
  return invoke<void>("export_to_file", { scanId, format, path });
}

export async function listPresets(): Promise<PresetInfo[]> {
  return invoke<PresetInfo[]>("list_presets");
}

export async function savePreset(
  name: string,
  config: GuiScanConfig,
): Promise<void> {
  return invoke<void>("save_preset", { name, config });
}

export async function loadPreset(name: string): Promise<GuiScanConfig> {
  return invoke<GuiScanConfig>("load_preset", { name });
}

export async function deletePreset(name: string): Promise<void> {
  return invoke<void>("delete_preset", { name });
}

export async function importScanFromFile(
  path: string,
): Promise<ScanHistoryEntry> {
  return invoke<ScanHistoryEntry>("import_scan_from_file", { path });
}
