<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Collapsible from "../shared/Collapsible.svelte";
  import Toggle from "../shared/Toggle.svelte";
</script>

<Collapsible title="Watch Mode">
  <div class="watch-row">
    <Toggle
      label="Enable Watch Mode"
      bind:checked={scanConfig.watchEnabled}
    />
    {#if scanConfig.watchEnabled}
      <div class="interval-field">
        <label for="watch-interval" class="label">Interval (seconds)</label>
        <input
          id="watch-interval"
          type="number"
          class="input"
          min="10"
          max="86400"
          bind:value={scanConfig.watchIntervalSecs}
        />
      </div>
    {/if}
  </div>
  {#if scanConfig.watchEnabled}
    <p class="watch-hint text-muted">
      Rescans targets every {scanConfig.watchIntervalSecs}s and reports changes. Use Stop to end.
    </p>
  {/if}
</Collapsible>

<style>
  .watch-row {
    display: flex;
    align-items: center;
    gap: var(--space-md);
    flex-wrap: wrap;
  }

  .interval-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .input {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 13px;
    width: 100px;
  }

  .input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .watch-hint {
    font-size: 12px;
    margin-top: var(--space-xs);
  }
</style>
