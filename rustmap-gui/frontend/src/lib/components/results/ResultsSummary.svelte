<script lang="ts">
  import { scanState } from "../../stores/scanState.svelte";
  import { formatDuration } from "../../utils/formatters";
  import Badge from "../shared/Badge.svelte";

  const totalDuration = $derived(
    scanState.finalResult?.total_duration ?? null,
  );
</script>

<div class="summary">
  <Badge variant="info">{scanState.hostResults.length} hosts scanned</Badge>
  <Badge variant="success">{scanState.hostsUp} up</Badge>
  <Badge variant="info">{scanState.openPortCount} open ports</Badge>
  {#if totalDuration}
    <Badge variant="muted">{formatDuration(totalDuration)}</Badge>
  {/if}
</div>

<style>
  .summary {
    display: flex;
    gap: var(--space-sm);
    flex-wrap: wrap;
  }
</style>
