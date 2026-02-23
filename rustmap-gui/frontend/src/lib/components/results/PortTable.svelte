<script lang="ts">
  import type { Port } from "../../types";
  import ScriptResults from "./ScriptResults.svelte";

  interface Props {
    ports: Port[];
  }

  let { ports }: Props = $props();

  function stateClass(state: string): string {
    switch (state) {
      case "open":
        return "state-open";
      case "closed":
        return "state-closed";
      case "filtered":
      case "openfiltered":
      case "closedfiltered":
      case "unfiltered":
        return "state-filtered";
      default:
        return "";
    }
  }

  function serviceName(port: Port): string {
    return port.service_info?.name ?? port.service ?? "—";
  }

  function serviceVersion(port: Port): string {
    if (!port.service_info) return "";
    const parts = [
      port.service_info.product,
      port.service_info.version,
      port.service_info.info ? `(${port.service_info.info})` : null,
    ].filter(Boolean);
    return parts.join(" ");
  }
</script>

<div class="port-table-wrapper">
  <table class="port-table">
    <thead>
      <tr>
        <th>Port</th>
        <th>State</th>
        <th>Service</th>
        <th>Version</th>
        <th>Reason</th>
      </tr>
    </thead>
    <tbody>
      {#each ports as port}
        <tr class={stateClass(port.state)}>
          <td class="mono">{port.number}/{port.protocol.toLowerCase()}</td>
          <td class="state-cell">{port.state}</td>
          <td>{serviceName(port)}</td>
          <td class="text-muted">{serviceVersion(port)}</td>
          <td class="text-muted">{port.reason ?? ""}</td>
        </tr>
        {#if (port.script_results ?? []).length > 0}
          <tr class="script-row">
            <td colspan="5">
              <ScriptResults scripts={port.script_results ?? []} />
            </td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
</div>

<style>
  .port-table-wrapper {
    overflow-x: auto;
  }

  .port-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    text-align: left;
    padding: var(--space-xs) var(--space-sm);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border-subtle);
  }

  td {
    padding: var(--space-xs) var(--space-sm);
    border-bottom: 1px solid var(--border-subtle);
  }

  tr.state-open .state-cell {
    color: var(--port-open);
    font-weight: 600;
  }

  tr.state-closed .state-cell {
    color: var(--port-closed);
  }

  tr.state-filtered .state-cell {
    color: var(--port-filtered);
  }

  .script-row td {
    padding: var(--space-xs) var(--space-md);
    background: var(--bg-base);
  }
</style>
