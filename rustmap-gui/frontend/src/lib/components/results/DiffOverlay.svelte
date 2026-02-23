<script lang="ts">
  import type { ScanDiff } from "../../types";

  interface Props {
    diff: ScanDiff;
    onclose: () => void;
  }

  let { diff, onclose }: Props = $props();

  const hasChanges = $derived(
    diff.new_hosts.length > 0 ||
    diff.removed_hosts.length > 0 ||
    diff.port_changes.length > 0,
  );
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<div class="overlay-backdrop" onclick={onclose} onkeydown={(e) => { if (e.key === "Escape") onclose(); }} role="presentation">
  <div class="overlay" onclick={(e) => e.stopPropagation()} role="dialog" aria-label="Scan Comparison" tabindex="-1">
    <div class="overlay-header">
      <h3 class="overlay-title">Scan Comparison</h3>
      <button class="close-btn" onclick={onclose} aria-label="Close">{"\u2715"}</button>
    </div>

    {#if !hasChanges}
      <p class="no-changes text-muted">No differences found between these scans.</p>
    {:else}
      <div class="diff-content">
        {#if diff.new_hosts.length > 0}
          <div class="diff-section">
            <h4 class="section-title new">New Hosts ({diff.new_hosts.length})</h4>
            <div class="host-list">
              {#each diff.new_hosts as host}
                <span class="host-badge new">{host}</span>
              {/each}
            </div>
          </div>
        {/if}

        {#if diff.removed_hosts.length > 0}
          <div class="diff-section">
            <h4 class="section-title removed">Removed Hosts ({diff.removed_hosts.length})</h4>
            <div class="host-list">
              {#each diff.removed_hosts as host}
                <span class="host-badge removed">{host}</span>
              {/each}
            </div>
          </div>
        {/if}

        {#if diff.port_changes.length > 0}
          <div class="diff-section">
            <h4 class="section-title changed">Port Changes ({diff.port_changes.length})</h4>
            <div class="changes-table">
              <div class="table-header">
                <span>Host</span>
                <span>Port</span>
                <span>Protocol</span>
                <span>Old State</span>
                <span>New State</span>
              </div>
              {#each diff.port_changes as change}
                <div class="table-row">
                  <span class="mono">{change.ip}</span>
                  <span class="mono">{change.port}</span>
                  <span>{change.protocol}</span>
                  <span class="state old">{change.old_state ?? "—"}</span>
                  <span class="state new">{change.new_state ?? "—"}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .overlay-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 900;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .overlay {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    max-width: 640px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
  }

  .overlay-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--space-md);
  }

  .overlay-title {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 16px;
    padding: 4px;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .no-changes {
    font-size: 14px;
    padding: var(--space-md) 0;
    text-align: center;
  }

  .diff-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .diff-section {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .section-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .section-title.new {
    color: var(--status-success);
  }

  .section-title.removed {
    color: var(--status-error);
  }

  .section-title.changed {
    color: var(--status-warning);
  }

  .host-list {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-xs);
  }

  .host-badge {
    font-family: var(--font-mono);
    font-size: 12px;
    padding: 2px 8px;
    border-radius: var(--radius-sm);
  }

  .host-badge.new {
    background: rgba(45, 212, 168, 0.15);
    color: var(--status-success);
  }

  .host-badge.removed {
    background: rgba(255, 92, 92, 0.15);
    color: var(--status-error);
  }

  .changes-table {
    display: flex;
    flex-direction: column;
    font-size: 12px;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }

  .table-header {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
    gap: var(--space-xs);
    padding: var(--space-xs) var(--space-sm);
    background: var(--bg-elevated);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    font-size: 11px;
  }

  .table-row {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
    gap: var(--space-xs);
    padding: var(--space-xs) var(--space-sm);
    border-top: 1px solid var(--border-subtle);
  }

  .state.old {
    color: var(--status-error);
  }

  .state.new {
    color: var(--status-success);
  }
</style>
