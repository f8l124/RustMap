<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Toggle from "../shared/Toggle.svelte";
</script>

<div class="toggles">
  <Toggle
    label="Service Detection (-sV)"
    bind:checked={scanConfig.serviceDetection}
  />
  <Toggle
    label="OS Detection (-O)"
    bind:checked={scanConfig.osDetection}
  />
  <Toggle
    label="Skip Discovery (-Pn)"
    bind:checked={scanConfig.skipDiscovery}
  />
</div>

<style>
  .toggles {
    display: flex;
    gap: var(--space-md);
    flex-wrap: wrap;
  }
</style>
