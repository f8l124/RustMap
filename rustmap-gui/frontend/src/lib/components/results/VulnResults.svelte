<script lang="ts">
  import type { HostVulnResult } from "../../types";
  import Collapsible from "../shared/Collapsible.svelte";

  interface Props {
    results: HostVulnResult[];
  }

  let { results }: Props = $props();

  function cvssColor(score: number | null): string {
    if (score === null) return "#888888";
    if (score >= 9) return "#ff3333";
    if (score >= 7) return "#ff8c00";
    if (score >= 4) return "#ffc94d";
    return "#4f8cff";
  }

  function cvssLabel(score: number | null): string {
    if (score === null) return "N/A";
    if (score >= 9) return "Critical";
    if (score >= 7) return "High";
    if (score >= 4) return "Medium";
    return "Low";
  }

  const totalVulns = $derived(
    results.reduce((sum, h) => sum + h.port_vulns.reduce((s, p) => s + p.vulns.length, 0), 0),
  );
</script>

<Collapsible title="Vulnerabilities ({totalVulns} found)">
  <div class="vuln-list">
    {#each results as hostResult}
      <div class="host-vulns">
        <div class="host-header">
          <span class="host-ip mono">{hostResult.ip}</span>
          {#if hostResult.risk_score !== null}
            <span class="risk-badge" style="color: {cvssColor(hostResult.risk_score)}">
              Risk: {hostResult.risk_score.toFixed(1)}
            </span>
          {/if}
        </div>
        {#each hostResult.port_vulns as portVuln}
          <div class="port-vulns">
            <div class="port-header">
              <span class="mono">{portVuln.port}/{portVuln.protocol}</span>
              {#if portVuln.product}
                <span class="text-secondary">{portVuln.product}{portVuln.version ? ` ${portVuln.version}` : ""}</span>
              {/if}
            </div>
            {#each portVuln.vulns as vuln}
              <div class="vuln-item">
                <div class="vuln-header">
                  <span class="cve-id mono">{vuln.cve_id}</span>
                  <span class="cvss-badge" style="background: {cvssColor(vuln.cvss_score)}20; color: {cvssColor(vuln.cvss_score)}">
                    {vuln.cvss_score !== null ? vuln.cvss_score.toFixed(1) : "?"} {cvssLabel(vuln.cvss_score)}
                  </span>
                </div>
                <p class="vuln-desc">{vuln.description}</p>
              </div>
            {/each}
          </div>
        {/each}
      </div>
    {/each}
  </div>
</Collapsible>

<style>
  .vuln-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .host-vulns {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .host-header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: 14px;
    font-weight: 600;
  }

  .host-ip {
    color: var(--text-primary);
  }

  .risk-badge {
    font-size: 12px;
    font-weight: 600;
  }

  .port-vulns {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    padding-left: var(--space-md);
  }

  .port-header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: 13px;
    color: var(--text-primary);
  }

  .vuln-item {
    padding: var(--space-xs) var(--space-sm);
    border-left: 2px solid var(--border-subtle);
    margin-left: var(--space-sm);
  }

  .vuln-header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }

  .cve-id {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .cvss-badge {
    font-size: 11px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: var(--radius-sm);
  }

  .vuln-desc {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 2px;
    line-height: 1.4;
  }
</style>
