<script lang="ts">
  import { resultFilter } from "../../stores/resultFilter.svelte";
  import HostCard from "./HostCard.svelte";
</script>

<div class="host-list">
  {#each resultFilter.filteredHosts as hostResult (hostResult.host.ip)}
    <HostCard {hostResult} />
  {:else}
    {#if resultFilter.hasActiveFilters}
      <p class="no-match text-muted">No hosts match the current filters</p>
    {/if}
  {/each}
</div>

<style>
  .host-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .no-match {
    text-align: center;
    font-size: 13px;
    padding: var(--space-md);
  }
</style>
