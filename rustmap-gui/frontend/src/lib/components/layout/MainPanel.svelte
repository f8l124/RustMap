<script lang="ts">
  import ScanConfigPanel from "../config/ScanConfigPanel.svelte";
  import ProgressBar from "../progress/ProgressBar.svelte";
  import ResultsPanel from "../results/ResultsPanel.svelte";
  import EmptyState from "../results/EmptyState.svelte";
  import { scanState } from "../../stores/scanState.svelte";

  const errorConfig = $derived.by(() => {
    switch (scanState.errorKind) {
      case "privilege":
        return {
          icon: "\u26A0",
          title: "Privilege Error",
          hint: "This scan type requires administrator/root privileges. Try running as admin, or use TCP Connect (-sT) which works unprivileged.",
          cssClass: "error-privilege",
        };
      case "config":
        return {
          icon: "\u2699",
          title: "Configuration Error",
          hint: "Check your scan targets and port specification.",
          cssClass: "error-config",
        };
      case "backend":
        return {
          icon: "\u26A1",
          title: "Backend Error",
          hint: "An unexpected error occurred in the scan engine.",
          cssClass: "error-backend",
        };
      default:
        return {
          icon: "\u2716",
          title: "Scan Error",
          hint: null,
          cssClass: "error-scan",
        };
    }
  });
</script>

<main class="main-panel">
  <ScanConfigPanel />
  {#if scanState.isScanning}
    <ProgressBar />
  {/if}
  {#if scanState.error}
    <div class="error-banner {errorConfig.cssClass}">
      <div class="error-content">
        <span class="error-icon">{errorConfig.icon}</span>
        <div class="error-text">
          <span class="error-title">{errorConfig.title}:</span>
          <span class="error-message">{scanState.error}</span>
          {#if errorConfig.hint}
            <span class="error-hint">{errorConfig.hint}</span>
          {/if}
        </div>
      </div>
      <button class="error-dismiss" onclick={() => scanState.dismissError()} title="Dismiss">{"\u2715"}</button>
    </div>
  {/if}
  {#if scanState.phase === "complete" || scanState.hostResults.length > 0}
    <ResultsPanel />
  {:else if scanState.phase === "idle"}
    <EmptyState />
  {/if}
</main>

<style>
  .main-panel {
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    padding: var(--space-md);
    gap: var(--space-md);
  }

  .error-banner {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-sm);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
  }

  .error-scan {
    background: rgba(255, 92, 92, 0.1);
    border: 1px solid var(--status-error);
    color: var(--status-error);
  }

  .error-privilege {
    background: rgba(255, 201, 77, 0.1);
    border: 1px solid var(--status-warning);
    color: var(--status-warning);
  }

  .error-config {
    background: rgba(79, 140, 255, 0.1);
    border: 1px solid var(--status-info);
    color: var(--status-info);
  }

  .error-backend {
    background: rgba(255, 92, 92, 0.1);
    border: 1px solid var(--status-error);
    color: var(--status-error);
  }

  .error-content {
    display: flex;
    gap: var(--space-sm);
    align-items: flex-start;
    flex: 1;
  }

  .error-icon {
    font-size: 16px;
    flex-shrink: 0;
    line-height: 1.4;
  }

  .error-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 13px;
    line-height: 1.4;
  }

  .error-title {
    font-weight: 600;
  }

  .error-message {
    color: var(--text-primary);
  }

  .error-hint {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  .error-dismiss {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 14px;
    padding: 2px 4px;
    opacity: 0.7;
    flex-shrink: 0;
  }

  .error-dismiss:hover {
    opacity: 1;
  }
</style>
