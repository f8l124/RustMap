<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";

  let preset = $state("default");

  function onPresetChange() {
    scanConfig.topPorts = null;
    switch (preset) {
      case "default":
        scanConfig.ports = "";
        break;
      case "top100":
        scanConfig.ports = "";
        scanConfig.topPorts = 100;
        break;
      case "all":
        scanConfig.ports = "1-65535";
        break;
      case "common-web":
        scanConfig.ports = "80,443,8080,8443";
        break;
      case "custom":
        break;
    }
  }
</script>

<div class="field">
  <label for="ports" class="label">Ports</label>
  <div class="port-row">
    <select
      class="select"
      bind:value={preset}
      onchange={onPresetChange}
    >
      <option value="default">Top 1000 (default)</option>
      <option value="top100">Top 100 (-F)</option>
      <option value="common-web">Common Web</option>
      <option value="all">All (1-65535)</option>
      <option value="custom">Custom</option>
    </select>
    {#if preset === "custom"}
      <input
        id="ports"
        type="text"
        class="input mono"
        placeholder="80,443,1-1024"
        bind:value={scanConfig.ports}
      />
    {/if}
  </div>
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    flex: 1;
    min-width: 160px;
  }

  .label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .port-row {
    display: flex;
    gap: var(--space-xs);
  }

  .select,
  .input {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 13px;
  }

  .select:focus,
  .input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .input {
    flex: 1;
  }
</style>
