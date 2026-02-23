<script lang="ts">
  import ResultsSummary from "./ResultsSummary.svelte";
  import HostList from "./HostList.svelte";
  import FilterBar from "./FilterBar.svelte";
  import ExportControls from "./ExportControls.svelte";
  import VulnResults from "./VulnResults.svelte";
  import { scanState } from "../../stores/scanState.svelte";
  import { checkVulns } from "../../tauri/commands";
  import { toasts } from "../../stores/toast.svelte";
  import type { HostVulnResult } from "../../types";

  let vulnResults = $state<HostVulnResult[]>([]);
  let vulnLoading = $state(false);

  async function runVulnCheck() {
    if (!scanState.scanId) return;
    vulnLoading = true;
    try {
      vulnResults = await checkVulns(scanState.scanId);
      if (vulnResults.length === 0) {
        toasts.info("No vulnerabilities found");
      }
    } catch (e) {
      toasts.error("Vuln check failed: " + String(e));
    } finally {
      vulnLoading = false;
    }
  }
</script>

<section class="results">
  <div class="results-header">
    <ResultsSummary />
    {#if scanState.phase === "complete"}
      <div class="header-actions">
        <button
          class="vuln-btn"
          onclick={runVulnCheck}
          disabled={vulnLoading}
          title="Check for known CVEs"
        >
          {vulnLoading ? "Checking..." : "Check CVEs"}
        </button>
        <ExportControls />
      </div>
    {/if}
  </div>
  <FilterBar />
  {#if vulnResults.length > 0}
    <VulnResults results={vulnResults} />
  {/if}
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

  .header-actions {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }

  .vuln-btn {
    font-size: 12px;
    padding: var(--space-xs) var(--space-sm);
    background: none;
    border: 1px solid var(--status-warning);
    border-radius: var(--radius-sm);
    color: var(--status-warning);
    cursor: pointer;
  }

  .vuln-btn:hover:not(:disabled) {
    background: rgba(255, 201, 77, 0.1);
  }

  .vuln-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
