<script lang="ts">
  import type { HostScanResult } from "../../types";
  import { formatLatency, formatDuration } from "../../utils/formatters";
  import { resultFilter } from "../../stores/resultFilter.svelte";
  import Badge from "../shared/Badge.svelte";
  import PortTable from "./PortTable.svelte";
  import OsInfo from "./OsInfo.svelte";
  import ScriptResults from "./ScriptResults.svelte";

  interface Props {
    hostResult: HostScanResult;
  }

  let { hostResult }: Props = $props();
  let expanded = $state(false);

  const openPorts = $derived(
    hostResult.ports.filter((p) => p.state === "open").length,
  );
  const statusVariant = $derived(
    hostResult.host_status === "Up"
      ? ("success" as const)
      : hostResult.host_status === "Down"
        ? ("error" as const)
        : ("muted" as const),
  );
  const osHint = $derived(
    hostResult.os_fingerprint?.os_family ?? null,
  );
  const hasScanError = $derived(
    hostResult.scan_error != null && hostResult.scan_error.length > 0,
  );
  const visiblePorts = $derived(resultFilter.filteredPorts(hostResult));
</script>

<div class="host-card" class:expanded class:has-error={hasScanError}>
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="card-header" role="button" tabindex="0" onclick={() => (expanded = !expanded)}>
    <span class="host-ip mono">{hostResult.host.ip}</span>
    {#if hostResult.host.hostname}
      <span class="hostname text-muted">({hostResult.host.hostname})</span>
    {/if}
    <Badge variant={statusVariant}>{hostResult.host_status}</Badge>
    {#if hasScanError}
      <Badge variant="error">scan error</Badge>
    {:else if openPorts > 0}
      <Badge variant="success">{openPorts} open</Badge>
    {/if}
    {#if osHint}
      <span class="os-hint text-muted">{osHint}</span>
    {/if}
    <span class="spacer"></span>
    <span class="latency text-muted mono">
      {formatLatency(hostResult.discovery_latency)}
    </span>
    <span class="expand-icon">{expanded ? "\u25BC" : "\u25B6"}</span>
  </div>

  {#if expanded}
    <div class="card-body">
      {#if hasScanError}
        <div class="scan-error-detail">
          <span class="error-label">Scan failed:</span>
          <span class="error-msg">{hostResult.scan_error}</span>
        </div>
      {/if}

      {#if visiblePorts.length > 0}
        <PortTable ports={visiblePorts} />
      {:else if !hasScanError}
        <p class="no-data text-muted">No ports match filters</p>
      {/if}

      {#if hostResult.host.geo_info}
        <div class="geo-info">
          <span class="section-label">GeoIP</span>
          <div class="geo-details">
            {#if hostResult.host.geo_info.country}
              <span>{hostResult.host.geo_info.country_code ?? ""} - {hostResult.host.geo_info.country}</span>
            {/if}
            {#if hostResult.host.geo_info.city}
              <span>{hostResult.host.geo_info.city}</span>
            {/if}
            {#if hostResult.host.geo_info.asn}
              <span>AS{hostResult.host.geo_info.asn} {hostResult.host.geo_info.as_org ?? ""}</span>
            {/if}
          </div>
        </div>
      {/if}

      {#if hostResult.os_fingerprint}
        <OsInfo fingerprint={hostResult.os_fingerprint} />
      {/if}

      {#if (hostResult.host_script_results ?? []).length > 0}
        <ScriptResults scripts={hostResult.host_script_results ?? []} />
      {/if}

      <div class="host-meta text-muted">
        <span>Port scan: {formatDuration(hostResult.scan_duration)}</span>
      </div>
    </div>
  {/if}
</div>

<style>
  .host-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .host-card.expanded {
    border-color: var(--border-default);
  }

  .host-card.has-error {
    border-color: var(--status-error);
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    padding: var(--space-sm) var(--space-md);
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
    font-size: 13px;
    user-select: none;
  }

  .card-header:hover {
    background: var(--bg-elevated);
  }

  .host-ip {
    font-weight: 600;
    font-size: 14px;
  }

  .hostname {
    font-size: 12px;
  }

  .os-hint {
    font-size: 12px;
  }

  .spacer {
    flex: 1;
  }

  .latency {
    font-size: 12px;
  }

  .expand-icon {
    font-size: 10px;
    color: var(--text-muted);
    margin-left: var(--space-xs);
    transition: transform 0.15s;
  }

  .host-card.expanded .expand-icon {
    transform: rotate(0deg);
  }

  .card-body {
    padding: var(--space-md);
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .no-data {
    font-size: 13px;
    padding: var(--space-xs) 0;
  }

  .scan-error-detail {
    background: rgba(255, 92, 92, 0.1);
    border: 1px solid var(--status-error);
    border-radius: var(--radius-sm);
    padding: var(--space-sm) var(--space-md);
    font-size: 13px;
  }

  .error-label {
    font-weight: 600;
    color: var(--status-error);
  }

  .error-msg {
    color: var(--text-primary);
  }

  .host-meta {
    font-size: 12px;
    padding-top: var(--space-xs);
    border-top: 1px solid var(--border-subtle);
  }

  .geo-info {
    font-size: 13px;
  }

  .geo-info .section-label {
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-muted);
    letter-spacing: 0.05em;
  }

  .geo-details {
    display: flex;
    gap: var(--space-md);
    flex-wrap: wrap;
    margin-top: var(--space-xs);
    color: var(--text-secondary);
  }
</style>
