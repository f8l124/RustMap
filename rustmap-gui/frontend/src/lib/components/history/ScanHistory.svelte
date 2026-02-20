<script lang="ts">
  import { scanHistory } from "../../stores/scanHistory.svelte";
  import ScanHistoryItem from "./ScanHistoryItem.svelte";
</script>

<div class="history">
  <h3 class="history-title">Scan History</h3>
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

  .history-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
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
</style>
