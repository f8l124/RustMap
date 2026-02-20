<script lang="ts">
  import { privileges } from "../../stores/privileges.svelte";
  import { scanState } from "../../stores/scanState.svelte";
</script>

<footer class="status-bar">
  <span class="status-item">
    {#if privileges.isPrivileged}
      <span class="badge badge-success">Privileged</span>
    {:else}
      <span class="badge badge-warning">Unprivileged</span>
    {/if}
  </span>
  <span class="status-item text-muted">
    {#if scanState.isScanning}
      Scanning... {scanState.hostsCompleted}/{scanState.hostsTotal}
    {:else if scanState.phase === "complete"}
      Scan complete
    {:else}
      Ready
    {/if}
  </span>
  <span class="status-item text-muted">v0.1.0</span>
</footer>

<style>
  .status-bar {
    grid-column: 1 / -1;
    display: flex;
    align-items: center;
    gap: var(--space-md);
    padding: var(--space-xs) var(--space-md);
    background: var(--bg-surface);
    border-top: 1px solid var(--border-subtle);
    font-size: 12px;
  }

  .status-item {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
  }

  .badge {
    padding: 1px 6px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 600;
  }

  .badge-success {
    background: rgba(45, 212, 168, 0.15);
    color: var(--status-success);
  }

  .badge-warning {
    background: rgba(255, 201, 77, 0.15);
    color: var(--status-warning);
  }
</style>
