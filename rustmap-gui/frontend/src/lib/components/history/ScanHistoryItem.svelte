<script lang="ts">
  import type { ScanHistoryEntry, ScanResult } from "../../types";
  import { formatTimestamp } from "../../utils/formatters";
  import { scanState } from "../../stores/scanState.svelte";
  import { exportResults } from "../../tauri/commands";

  interface Props {
    entry: ScanHistoryEntry;
  }

  let { entry }: Props = $props();

  function formatDurationMs(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    const secs = ms / 1000;
    if (secs < 60) return `${secs.toFixed(1)}s`;
    const mins = Math.floor(secs / 60);
    const remSecs = Math.round(secs % 60);
    return `${mins}m${remSecs}s`;
  }

  async function loadResult() {
    try {
      const json = await exportResults(entry.scan_id, "json");
      const result: ScanResult = JSON.parse(json);
      scanState.onScanComplete(result);
      scanState.scanId = entry.scan_id;
    } catch (e) {
      console.error("Failed to load scan result:", e);
    }
  }
</script>

<button class="history-item" onclick={loadResult}>
  <div class="item-header">
    <span class="item-time text-muted">{formatTimestamp(entry.started_at)}</span>
    <span class="item-duration mono text-muted">
      {formatDurationMs(entry.total_duration_ms)}
    </span>
  </div>
  <div class="item-body">
    <span class="item-hosts">{entry.num_hosts} hosts, {entry.num_services} services</span>
  </div>
</button>

<style>
  .history-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: var(--space-sm);
    background: none;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    font-size: 13px;
    width: 100%;
  }

  .history-item:hover {
    background: var(--bg-elevated);
    border-color: var(--border-subtle);
  }

  .item-header {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
  }

  .item-body {
    font-size: 13px;
  }

  .item-hosts {
    font-weight: 500;
  }
</style>
