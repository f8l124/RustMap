<script lang="ts">
  import { getAppVersion } from "../../tauri/commands";
  import { privileges } from "../../stores/privileges.svelte";
  import { scanState } from "../../stores/scanState.svelte";
  import { theme } from "../../stores/theme.svelte";
  import { updater } from "../../stores/updater.svelte";

  let appVersion = $state("...");
  getAppVersion().then((v) => (appVersion = v));
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
  <span class="spacer"></span>
  <button class="theme-toggle" onclick={() => theme.toggle()} title="Toggle theme" aria-label="Toggle theme">
    {#if theme.current === "dark"}
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="5"/>
        <line x1="12" y1="1" x2="12" y2="3"/>
        <line x1="12" y1="21" x2="12" y2="23"/>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
        <line x1="1" y1="12" x2="3" y2="12"/>
        <line x1="21" y1="12" x2="23" y2="12"/>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
      </svg>
    {:else}
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
      </svg>
    {/if}
  </button>
  {#if updater.available}
    <button
      class="update-badge"
      onclick={() => updater.downloadAndInstall()}
      disabled={updater.downloading}
      title="Click to update and restart"
    >
      {updater.downloading ? "Updating..." : `Update v${updater.version}`}
    </button>
  {/if}
  <span class="status-item text-muted">v{appVersion}</span>
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

  .spacer {
    flex: 1;
  }

  .theme-toggle {
    background: none;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    cursor: pointer;
    padding: 2px 6px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .theme-toggle:hover {
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .update-badge {
    font-size: 11px;
    font-weight: 600;
    padding: 1px 8px;
    border-radius: var(--radius-sm);
    background: rgba(45, 212, 168, 0.15);
    color: var(--status-success);
    border: 1px solid rgba(45, 212, 168, 0.3);
    cursor: pointer;
  }

  .update-badge:hover:not(:disabled) {
    background: rgba(45, 212, 168, 0.25);
  }

  .update-badge:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
