<script lang="ts">
  import ResultsSummary from "./ResultsSummary.svelte";
  import HostList from "./HostList.svelte";
  import FilterBar from "./FilterBar.svelte";
  import ExportControls from "./ExportControls.svelte";
  import { scanState } from "../../stores/scanState.svelte";
</script>

<section class="results">
  <div class="results-header">
    <ResultsSummary />
    {#if scanState.phase === "complete"}
      <ExportControls />
    {/if}
  </div>
  <FilterBar />
  <HostList />
</section>

<style>
  .results {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-sm);
  }
</style>
