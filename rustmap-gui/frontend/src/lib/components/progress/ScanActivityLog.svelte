<script lang="ts">
  import { scanState } from "../../stores/scanState.svelte";

  let expanded = $state(true);
  let logContainer: HTMLDivElement | undefined = $state();

  const entryCount = $derived(scanState.logEntries.length);

  // Auto-collapse when scan completes
  $effect(() => {
    if (!scanState.isScanning && scanState.phase === "complete") {
      expanded = false;
    }
  });

  // Auto-expand when a new scan starts
  $effect(() => {
    if (scanState.isScanning) {
      expanded = true;
    }
  });

  // Auto-scroll when new entries arrive
  $effect(() => {
    const _len = scanState.logEntries.length;
    if (expanded && logContainer) {
      requestAnimationFrame(() => {
        if (logContainer) {
          logContainer.scrollTop = logContainer.scrollHeight;
        }
      });
    }
  });
</script>

{#if scanState.logEntries.length > 0}
  <div class="activity-log" class:expanded>
    <button class="log-header" onclick={() => (expanded = !expanded)}>
      <span class="log-icon">{expanded ? "\u25BC" : "\u25B6"}</span>
      <span class="log-title">Activity Log ({entryCount})</span>
    </button>
    {#if expanded}
      <div class="log-entries" bind:this={logContainer}>
        {#each scanState.logEntries as entry}
          <div class="log-entry">
            <span class="log-time">{entry.relativeTime}</span>
            <span class="log-msg">{entry.message}</span>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<style>
  .activity-log {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .log-header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    padding: var(--space-xs) var(--space-sm);
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    text-align: left;
  }

  .log-header:hover {
    color: var(--text-primary);
    background: var(--bg-elevated, var(--bg-base));
  }

  .log-icon {
    font-size: 9px;
    flex-shrink: 0;
    width: 12px;
  }

  .log-title {
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }

  .log-entries {
    max-height: 300px;
    overflow-y: scroll;
    padding: 0 var(--space-sm) var(--space-xs);
    border-top: 1px solid var(--border-subtle);
  }

  .log-entry {
    display: flex;
    gap: var(--space-sm);
    padding: 2px 0;
    font-size: 11px;
    font-family: var(--font-mono);
    line-height: 1.4;
  }

  .log-time {
    color: var(--text-muted);
    flex-shrink: 0;
    min-width: 36px;
  }

  .log-msg {
    color: var(--text-secondary);
  }
</style>
