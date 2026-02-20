<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import { scanState } from "../../stores/scanState.svelte";
  import { resultFilter } from "../../stores/resultFilter.svelte";
  import { startScan, stopScan } from "../../tauri/commands";
  import { parseError } from "../../utils/errorParser";

  async function handleScan() {
    if (!scanConfig.configValid || scanState.isScanning) return;
    scanState.onStarting();
    resultFilter.reset();
    try {
      await startScan(scanConfig.config);
    } catch (e) {
      const { message, kind } = parseError(e);
      scanState.onScanError(message, kind);
    }
  }

  async function handleStop() {
    if (scanState.scanId) {
      try {
        await stopScan(scanState.scanId);
      } catch (e) {
        console.error("Failed to stop scan:", e);
      }
    }
  }

  function handleClear() {
    scanState.reset();
    resultFilter.reset();
  }
</script>

<div class="actions">
  {#if scanState.isScanning}
    <button class="btn btn-stop" onclick={handleStop}>
      Stop
    </button>
  {:else}
    {#if scanState.phase === "complete" || scanState.phase === "error"}
      <button class="btn btn-clear" onclick={handleClear}>
        New Scan
      </button>
    {/if}
    <button
      class="btn btn-scan"
      onclick={handleScan}
      disabled={!scanConfig.configValid}
    >
      Scan
    </button>
  {/if}
</div>

<style>
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-sm);
  }

  .btn {
    padding: var(--space-sm) var(--space-lg);
    border: none;
    border-radius: var(--radius-sm);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-scan {
    background: var(--accent);
    color: #fff;
  }

  .btn-scan:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .btn-clear {
    background: var(--bg-elevated);
    color: var(--text-secondary);
    border: 1px solid var(--border-default);
  }

  .btn-clear:hover {
    background: var(--bg-surface);
    color: var(--text-primary);
  }

  .btn-stop {
    background: var(--status-error);
    color: #fff;
  }

  .btn-stop:hover {
    background: #e04040;
  }
</style>
