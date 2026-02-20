<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import { privileges } from "../../stores/privileges.svelte";
  import { SCAN_TYPES } from "../../utils/scanTypeInfo";
</script>

<div class="field">
  <label for="scan-type" class="label">Scan Type</label>
  <select id="scan-type" class="select" bind:value={scanConfig.scanType}>
    {#each SCAN_TYPES as st}
      <option
        value={st.flag}
        disabled={st.requiresPrivilege && !privileges.isPrivileged}
      >
        {st.label}{st.requiresPrivilege && !privileges.isPrivileged
          ? " (requires admin)"
          : ""}
      </option>
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

  option:disabled {
    color: var(--text-muted);
  }
</style>
