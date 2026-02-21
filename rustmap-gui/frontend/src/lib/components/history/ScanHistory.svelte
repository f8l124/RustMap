<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { scanHistory } from "../../stores/scanHistory.svelte";
  import { scanState } from "../../stores/scanState.svelte";
  import { importScanFromFile, exportResults } from "../../tauri/commands";
  import ScanHistoryItem from "./ScanHistoryItem.svelte";

  let clearing = $state(false);
  let importing = $state(false);

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
  {#if scanHistory.entries.length === 0}
    <p class="text-muted empty">No scans yet</p>
  {:else}
    <div class="history-list">
      {#each scanHistory.entries as entry}
        <ScanHistoryItem {entry} />
      {/each}
    </div>
  {/if}
</div>

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

  .import-btn:hover:not(:disabled) {
    color: var(--accent);
    background: rgba(79, 140, 255, 0.1);
  }

  .clear-btn:hover:not(:disabled) {
    color: var(--status-error);
    background: rgba(255, 92, 92, 0.1);
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
</style>
