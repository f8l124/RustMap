<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Collapsible from "../shared/Collapsible.svelte";
</script>

<Collapsible title="Advanced Options">
  <div class="grid">
    <div class="field">
      <label for="concurrency" class="label">Concurrency</label>
      <input
        id="concurrency"
        type="number"
        class="input"
        min="1"
        max="10000"
        bind:value={scanConfig.concurrency}
      />
    </div>
    <div class="field">
      <label for="timeout" class="label">Timeout (ms)</label>
      <input
        id="timeout"
        type="number"
        class="input"
        min="100"
        bind:value={scanConfig.timeoutMs}
      />
    </div>
    <div class="field">
      <label for="hostgroup" class="label">Max Hostgroup</label>
      <input
        id="hostgroup"
        type="number"
        class="input"
        min="1"
        max="65535"
        bind:value={scanConfig.maxHostgroup}
      />
    </div>
    <div class="field">
      <label for="host-timeout" class="label">Host Timeout (ms)</label>
      <input
        id="host-timeout"
        type="number"
        class="input"
        min="0"
        bind:value={scanConfig.hostTimeoutMs}
      />
    </div>
    <div class="field">
      <label for="min-rate" class="label">Min Rate (pkt/s)</label>
      <input
        id="min-rate"
        type="number"
        class="input"
        min="0"
        placeholder="—"
        bind:value={scanConfig.minRate}
      />
    </div>
    <div class="field">
      <label for="max-rate" class="label">Max Rate (pkt/s)</label>
      <input
        id="max-rate"
        type="number"
        class="input"
        min="0"
        placeholder="—"
        bind:value={scanConfig.maxRate}
      />
    </div>
  </div>
</Collapsible>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: var(--space-sm);
  }

  .field {
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
    width: 100%;
  }

  .input:focus {
    outline: none;
    border-color: var(--accent);
  }
</style>
