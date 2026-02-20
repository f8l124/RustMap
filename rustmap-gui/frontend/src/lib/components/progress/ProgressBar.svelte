<script lang="ts">
  import { scanState } from "../../stores/scanState.svelte";
  import { formatElapsed } from "../../utils/formatters";

  let elapsed = $state("0s");
  let interval: ReturnType<typeof setInterval> | null = null;

  $effect(() => {
    if (scanState.isScanning && scanState.startedAt) {
      interval = setInterval(() => {
        elapsed = formatElapsed(scanState.startedAt!);
      }, 1000);
    } else if (interval) {
      clearInterval(interval);
      interval = null;
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  });
</script>

<div class="progress">
  <div class="progress-info">
    <span class="progress-label">
      {scanState.hostsCompleted}/{scanState.hostsTotal} hosts
    </span>
    <span class="progress-time text-muted">{elapsed}</span>
    <span class="progress-percent">{scanState.progressPercent}%</span>
  </div>
  <div class="progress-track">
    <div
      class="progress-fill"
      class:complete={scanState.phase === "complete"}
      style="width: {scanState.progressPercent}%"
    ></div>
  </div>
</div>

<style>
  .progress {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .progress-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
  }

  .progress-label {
    font-weight: 600;
  }

  .progress-percent {
    color: var(--accent);
    font-weight: 600;
    font-family: var(--font-mono);
  }

  .progress-track {
    height: 6px;
    background: var(--bg-base);
    border-radius: 3px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 3px;
    transition: width 0.3s ease;
  }

  .progress-fill.complete {
    background: var(--status-success);
  }
</style>
