<script lang="ts">
  import { resultFilter } from "../../stores/resultFilter.svelte";
  import type { PortState, HostStatus } from "../../types";

  const stateOptions: { value: PortState; label: string; cssClass: string }[] = [
    { value: "open", label: "Open", cssClass: "chip-open" },
    { value: "closed", label: "Closed", cssClass: "chip-closed" },
    { value: "filtered", label: "Filtered", cssClass: "chip-filtered" },
  ];

  const statusOptions: { value: HostStatus; label: string }[] = [
    { value: "Up", label: "Up" },
    { value: "Down", label: "Down" },
  ];
</script>

<div class="filter-bar">
  <div class="filter-inputs">
    <input
      id="filter-search"
      type="text"
      class="filter-input mono"
      placeholder="Filter by IP or hostname..."
      bind:value={resultFilter.searchQuery}
    />
    <input
      type="text"
      class="filter-input filter-port mono"
      placeholder="Port (e.g., 80,443)"
      bind:value={resultFilter.portFilter}
    />
  </div>
  <div class="filter-chips">
    <span class="chip-group-label">State:</span>
    {#each stateOptions as opt}
      <button
        class="chip {opt.cssClass}"
        class:active={resultFilter.stateFilters.has(opt.value)}
        onclick={() => resultFilter.toggleStateFilter(opt.value)}
      >
        {opt.label}
      </button>
    {/each}
    <span class="chip-divider"></span>
    <span class="chip-group-label">Host:</span>
    {#each statusOptions as opt}
      <button
        class="chip"
        class:active={resultFilter.statusFilters.has(opt.value)}
        onclick={() => resultFilter.toggleStatusFilter(opt.value)}
      >
        {opt.value}
      </button>
    {/each}
    {#if resultFilter.hasActiveFilters}
      <button class="chip chip-clear" onclick={() => resultFilter.reset()}>
        Clear
      </button>
    {/if}
  </div>
  {#if resultFilter.hasActiveFilters}
    <span class="filter-count text-muted">
      {resultFilter.matchCount} of {resultFilter.totalCount} hosts
    </span>
  {/if}
</div>

<style>
  .filter-bar {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .filter-inputs {
    display: flex;
    gap: var(--space-xs);
  }

  .filter-input {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 12px;
    flex: 1;
  }

  .filter-port {
    max-width: 160px;
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .filter-input::placeholder {
    color: var(--text-muted);
  }

  .filter-chips {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    flex-wrap: wrap;
  }

  .chip-group-label {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }

  .chip-divider {
    width: 1px;
    height: 16px;
    background: var(--border-subtle);
    margin: 0 var(--space-xs);
  }

  .chip {
    padding: 1px 8px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--border-default);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    transition: all 0.15s;
  }

  .chip:hover {
    border-color: var(--text-secondary);
    color: var(--text-secondary);
  }

  .chip.active {
    border-color: var(--accent);
    background: rgba(79, 140, 255, 0.15);
    color: var(--accent);
  }

  .chip-open.active {
    border-color: var(--port-open);
    background: rgba(45, 212, 168, 0.15);
    color: var(--port-open);
  }

  .chip-closed.active {
    border-color: var(--port-closed);
    background: rgba(255, 92, 92, 0.15);
    color: var(--port-closed);
  }

  .chip-filtered.active {
    border-color: var(--port-filtered);
    background: rgba(255, 201, 77, 0.15);
    color: var(--port-filtered);
  }

  .chip-clear {
    border-color: var(--status-error);
    color: var(--status-error);
  }

  .chip-clear:hover {
    background: rgba(255, 92, 92, 0.1);
    border-color: var(--status-error);
    color: var(--status-error);
  }

  .filter-count {
    font-size: 12px;
    font-family: var(--font-mono);
  }
</style>
