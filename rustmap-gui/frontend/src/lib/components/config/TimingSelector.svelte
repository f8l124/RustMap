<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import { TIMING_TEMPLATES } from "../../utils/scanTypeInfo";
</script>

<div class="field">
  <label for="timing" class="label">Timing</label>
  <select id="timing" class="select" bind:value={scanConfig.timing}>
    {#each TIMING_TEMPLATES as t}
      <option value={t.value}>{t.label}</option>
    {/each}
  </select>
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    min-width: 160px;
  }

  .label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .select {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 13px;
  }

  .select:focus {
    outline: none;
    border-color: var(--accent);
  }
</style>
