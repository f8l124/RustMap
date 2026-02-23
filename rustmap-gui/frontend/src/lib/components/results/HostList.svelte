<script lang="ts">
  import { resultFilter } from "../../stores/resultFilter.svelte";
  import HostCard from "./HostCard.svelte";

  const PAGE_SIZE = 100;
  let displayLimit = $state(PAGE_SIZE);

  // Reset display limit when filtered results change substantially
  let prevFilteredCount = 0;
  $effect(() => {
    const count = resultFilter.filteredHosts.length;
    if (count < prevFilteredCount) {
      displayLimit = PAGE_SIZE;
    }
    prevFilteredCount = count;
  });

  let visibleHosts = $derived(resultFilter.filteredHosts.slice(0, displayLimit));
  let hasMore = $derived(resultFilter.filteredHosts.length > displayLimit);
  let remaining = $derived(resultFilter.filteredHosts.length - displayLimit);

  function showMore() {
    displayLimit += PAGE_SIZE;
  }

  function showAll() {
    displayLimit = resultFilter.filteredHosts.length;
  }
</script>

<div class="host-list">
  {#each visibleHosts as hostResult (hostResult.host.ip)}
    <HostCard {hostResult} />
  {:else}
    {#if resultFilter.hasActiveFilters}
      <p class="no-match text-muted">No hosts match the current filters</p>
    {/if}
  {/each}
  {#if hasMore}
    <div class="show-more">
      <button class="show-more-btn" onclick={showMore}>
        Show {Math.min(PAGE_SIZE, remaining)} more
      </button>
      <button class="show-all-btn" onclick={showAll}>
        Show all ({remaining} remaining)
      </button>
    </div>
  {/if}
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

  .show-more {
    display: flex;
    justify-content: center;
    gap: var(--space-sm);
    padding: var(--space-md) 0;
  }

  .show-more-btn,
  .show-all-btn {
    font-size: 12px;
    padding: var(--space-xs) var(--space-md);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-secondary);
    cursor: pointer;
  }

  .show-more-btn:hover,
  .show-all-btn:hover {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }
</style>
