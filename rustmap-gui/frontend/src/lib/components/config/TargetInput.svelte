<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
</script>

<div class="field">
  <label for="targets" class="label">Targets</label>
  <textarea
    id="targets"
    class="input mono"
    placeholder="IP, CIDR, range, or hostname (e.g., 192.168.1.0/24)"
    rows="2"
    bind:value={scanConfig.targets}
  ></textarea>
</div>

<style>
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
    padding: var(--space-sm);
    font-size: 13px;
    resize: vertical;
  }

  .input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .input::placeholder {
    color: var(--text-muted);
  }
</style>
