<script lang="ts">
  import { scanState } from "../../stores/scanState.svelte";
  import Badge from "../shared/Badge.svelte";
</script>

<div class="summary">
  <Badge variant="info">{scanState.hostResults.length} hosts scanned</Badge>
  <Badge variant="success">{scanState.hostsUp} up</Badge>
  <Badge variant="info">{scanState.openPortCount} open ports</Badge>
</div>

<style>
  .summary {
    display: flex;
    gap: var(--space-sm);
    flex-wrap: wrap;
  }
</style>
