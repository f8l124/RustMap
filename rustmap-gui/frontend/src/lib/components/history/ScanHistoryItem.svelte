<script lang="ts">
  import type { CheckpointInfo, ScanHistoryEntry, ScanResult } from "../../types";
  import { formatTimestamp } from "../../utils/formatters";
  import { scanState } from "../../stores/scanState.svelte";
  import { exportResults } from "../../tauri/commands";

  interface Props {
    entry: ScanHistoryEntry;
    selectable?: boolean;
    selected?: boolean;
    onselect?: () => void;
    checkpoint?: CheckpointInfo | null;
    onresume?: () => void;
  }

  let { entry, selectable = false, selected = false, onselect, checkpoint = null, onresume }: Props = $props();

  function formatDurationMs(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    const secs = ms / 1000;
    if (secs < 60) return `${secs.toFixed(1)}s`;
    const mins = Math.floor(secs / 60);
    const remSecs = Math.round(secs % 60);
    return `${mins}m${remSecs}s`;
  }

  async function handleClick() {
    if (selectable) {
      onselect?.();
    } else {
      await loadResult();
    }
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

  function handleResume(e: MouseEvent) {
    e.stopPropagation();
    onresume?.();
  }
</script>

<button class="history-item" class:selected onclick={handleClick}>
  <div class="item-header">
    {#if selectable}
      <span class="checkbox">{selected ? "\u2611" : "\u2610"}</span>
    {/if}
    <span class="item-time text-muted">{formatTimestamp(entry.started_at)}</span>
    <span class="item-duration mono text-muted">
      {formatDurationMs(entry.total_duration_ms)}
    </span>
  </div>
  <div class="item-body">
    <span class="item-hosts">{entry.num_hosts} hosts, {entry.num_services} services</span>
    {#if checkpoint}
      <span class="resume-badge" role="button" tabindex="0" onclick={handleResume} onkeydown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); handleResume(e as unknown as MouseEvent); } }}>
        Resume ({checkpoint.completed_count}/{checkpoint.total_hosts})
      </span>
    {/if}
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

  .history-item.selected {
    border-color: var(--accent);
    background: rgba(79, 140, 255, 0.08);
  }

  .item-header {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    align-items: center;
    gap: var(--space-xs);
  }

  .checkbox {
    font-size: 14px;
    color: var(--accent);
    flex-shrink: 0;
  }

  .item-body {
    font-size: 13px;
  }

  .item-hosts {
    font-weight: 500;
  }

  .resume-badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    color: var(--status-warning);
    background: rgba(230, 126, 34, 0.12);
    padding: 1px 6px;
    border-radius: var(--radius-sm);
    margin-left: var(--space-xs);
    cursor: pointer;
  }

  .resume-badge:hover {
    background: rgba(230, 126, 34, 0.25);
  }
</style>
