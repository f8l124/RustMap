<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { scanHistory } from "../../stores/scanHistory.svelte";
  import { scanState } from "../../stores/scanState.svelte";
  import { toasts } from "../../stores/toast.svelte";
  import { importScanFromFile, exportResults, diffScans, resumeScan } from "../../tauri/commands";
  import { parseError } from "../../utils/errorParser";
  import type { ScanDiff } from "../../types";
  import ScanHistoryItem from "./ScanHistoryItem.svelte";
  import DiffOverlay from "../results/DiffOverlay.svelte";

  let clearing = $state(false);
  let importing = $state(false);
  let compareMode = $state(false);
  let selectedIds = $state<string[]>([]);
  let diffResult = $state<ScanDiff | null>(null);
  let diffLoading = $state(false);

  function toggleCompare() {
    compareMode = !compareMode;
    selectedIds = [];
    diffResult = null;
  }

  function onSelect(scanId: string) {
    if (!compareMode) return;
    const idx = selectedIds.indexOf(scanId);
    if (idx >= 0) {
      selectedIds = selectedIds.filter((id) => id !== scanId);
    } else if (selectedIds.length < 2) {
      selectedIds = [...selectedIds, scanId];
    }
  }

  async function handleCompare() {
    if (selectedIds.length !== 2) return;
    diffLoading = true;
    try {
      // Order: older scan first
      const a = scanHistory.entries.find((e) => e.scan_id === selectedIds[0]);
      const b = scanHistory.entries.find((e) => e.scan_id === selectedIds[1]);
      let oldId: string, newId: string;
      if (a && b && a.started_at > b.started_at) {
        oldId = selectedIds[1];
        newId = selectedIds[0];
      } else {
        oldId = selectedIds[0];
        newId = selectedIds[1];
      }
      diffResult = await diffScans(oldId, newId);
    } catch (e) {
      toasts.error("Diff failed: " + String(e));
    } finally {
      diffLoading = false;
    }
  }

  async function handleResume(scanId: string) {
    if (scanState.isScanning) return;
    scanState.onStarting();
    try {
      await resumeScan(scanId);
      scanHistory.removeCheckpoint(scanId);
    } catch (e) {
      const { message, kind } = parseError(e);
      scanState.onScanError(message, kind);
    }
  }

  async function handleClear() {
    clearing = true;
    await scanHistory.clear();
    clearing = false;
  }

  async function handleImport() {
    if (importing) return;

    const selected = await open({
      multiple: false,
      filters: [
        { name: "JSON Scan Results", extensions: ["json"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });

    if (!selected) return;
    const path = typeof selected === "string" ? selected : selected[0];
    if (!path) return;

    importing = true;
    try {
      const entry = await importScanFromFile(path);
      scanHistory.addEntry(entry);

      // Auto-load imported result into the results view
      const json = await exportResults(entry.scan_id, "json");
      const result = JSON.parse(json);
      scanState.onScanComplete(result);
      scanState.scanId = entry.scan_id;
    } catch (e) {
      console.error("Failed to import scan:", e);
    } finally {
      importing = false;
    }
  }
</script>

<div class="history">
  <div class="history-header">
    <h3 class="history-title">Scan History</h3>
    <div class="history-actions">
      {#if scanHistory.entries.length >= 2}
        <button
          class="action-btn compare-btn"
          class:active={compareMode}
          onclick={toggleCompare}
          title={compareMode ? "Cancel compare" : "Compare two scans"}
        >
          {compareMode ? "Cancel" : "Diff"}
        </button>
      {/if}
      <button
        class="action-btn import-btn"
        onclick={handleImport}
        disabled={importing}
        title="Import scan from file"
      >
        {importing ? "..." : "+"}
      </button>
      {#if scanHistory.entries.length > 0}
        <button
          class="action-btn clear-btn"
          onclick={handleClear}
          disabled={clearing}
          title="Clear all history"
        >
          {clearing ? "..." : "Clear"}
        </button>
      {/if}
    </div>
  </div>
  {#if compareMode && selectedIds.length === 2}
    <button
      class="compare-go"
      onclick={handleCompare}
      disabled={diffLoading}
    >
      {diffLoading ? "Comparing..." : "Compare Selected"}
    </button>
  {:else if compareMode}
    <p class="compare-hint text-muted">Select 2 scans to compare</p>
  {/if}
  {#each scanHistory.checkpoints.filter((cp) => !scanHistory.entries.some((e) => e.scan_id === cp.scan_id)) as cp}
    <button
      class="checkpoint-item"
      onclick={() => handleResume(cp.scan_id)}
      disabled={scanState.isScanning}
    >
      <span class="cp-label">Interrupted scan</span>
      <span class="cp-progress text-muted">{cp.completed_count}/{cp.total_hosts} hosts</span>
      <span class="resume-action">Resume</span>
    </button>
  {/each}
  {#if scanHistory.entries.length === 0 && scanHistory.checkpoints.length === 0}
    <p class="text-muted empty">No scans yet</p>
  {:else if scanHistory.entries.length === 0}
    <!-- only orphaned checkpoints, no completed scans -->
  {:else}
    <div class="history-list">
      {#each scanHistory.entries as entry}
        <ScanHistoryItem
          {entry}
          selectable={compareMode}
          selected={selectedIds.includes(entry.scan_id)}
          onselect={() => onSelect(entry.scan_id)}
          checkpoint={scanHistory.getCheckpoint(entry.scan_id) ?? null}
          onresume={() => handleResume(entry.scan_id)}
        />
      {/each}
    </div>
  {/if}
</div>

{#if diffResult}
  <DiffOverlay diff={diffResult} onclose={() => { diffResult = null; }} />
{/if}

<style>
  .history {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: var(--space-md);
    overflow-y: auto;
  }

  .history-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--space-sm);
  }

  .history-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .history-actions {
    display: flex;
    gap: var(--space-xs);
    align-items: center;
  }

  .action-btn {
    font-size: 11px;
    color: var(--text-muted);
    background: none;
    border: none;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: var(--radius-sm);
  }

  .action-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .compare-btn:hover:not(:disabled) {
    color: var(--accent);
    background: rgba(79, 140, 255, 0.1);
  }

  .compare-btn.active {
    color: var(--accent);
    background: rgba(79, 140, 255, 0.15);
  }

  .import-btn:hover:not(:disabled) {
    color: var(--accent);
    background: rgba(79, 140, 255, 0.1);
  }

  .clear-btn:hover:not(:disabled) {
    color: var(--status-error);
    background: rgba(255, 92, 92, 0.1);
  }

  .compare-go {
    font-size: 12px;
    padding: var(--space-xs) var(--space-sm);
    margin-bottom: var(--space-sm);
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .compare-go:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .compare-hint {
    font-size: 12px;
    margin-bottom: var(--space-sm);
  }

  .empty {
    font-size: 13px;
    padding: var(--space-md) 0;
  }

  .history-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .checkpoint-item {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-sm);
    background: rgba(230, 126, 34, 0.08);
    border: 1px solid rgba(230, 126, 34, 0.25);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-size: 13px;
    color: var(--text-primary);
    margin-bottom: var(--space-xs);
    width: 100%;
    text-align: left;
  }

  .checkpoint-item:hover:not(:disabled) {
    background: rgba(230, 126, 34, 0.15);
  }

  .checkpoint-item:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .cp-label {
    font-weight: 600;
    font-size: 12px;
  }

  .cp-progress {
    font-size: 11px;
    flex: 1;
  }

  .resume-action {
    font-size: 11px;
    font-weight: 600;
    color: var(--status-warning);
  }
</style>
