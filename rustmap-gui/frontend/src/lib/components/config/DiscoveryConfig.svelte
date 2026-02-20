<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Collapsible from "../shared/Collapsible.svelte";

  const probes = [
    { id: "icmp_echo", label: "ICMP Echo (-PE)", hasPorts: false },
    { id: "tcp_syn", label: "TCP SYN (-PS)", hasPorts: true },
    { id: "tcp_ack", label: "TCP ACK (-PA)", hasPorts: true },
    { id: "icmp_timestamp", label: "ICMP Timestamp (-PP)", hasPorts: false },
    { id: "udp_ping", label: "UDP Ping (-PU)", hasPorts: true },
    { id: "arp_ping", label: "ARP Ping (-PR)", hasPorts: false },
    { id: "http_ping", label: "HTTP Ping (--PH)", hasPorts: true },
    { id: "https_ping", label: "HTTPS Ping (--PHT)", hasPorts: true },
  ] as const;

  const portBindings: Record<string, { get: () => string; set: (v: string) => void; placeholder: string }> = {
    tcp_syn: { get: () => scanConfig.tcpSynPorts, set: (v) => scanConfig.tcpSynPorts = v, placeholder: "443" },
    tcp_ack: { get: () => scanConfig.tcpAckPorts, set: (v) => scanConfig.tcpAckPorts = v, placeholder: "80" },
    udp_ping: { get: () => scanConfig.udpPingPorts, set: (v) => scanConfig.udpPingPorts = v, placeholder: "40125" },
    http_ping: { get: () => scanConfig.httpPorts, set: (v) => scanConfig.httpPorts = v, placeholder: "80" },
    https_ping: { get: () => scanConfig.httpsPorts, set: (v) => scanConfig.httpsPorts = v, placeholder: "443" },
  };

  function toggleMethod(id: string) {
    const methods = scanConfig.discoveryMethods;
    if (methods.includes(id)) {
      scanConfig.discoveryMethods = methods.filter((m) => m !== id);
    } else {
      scanConfig.discoveryMethods = [...methods, id];
    }
  }

  const isCustom = $derived(scanConfig.discoveryMode === "custom");
</script>

<Collapsible title="Host Discovery">
  <div class="discovery">
    <div class="field">
      <label for="discovery-mode" class="label">Discovery Mode</label>
      <select id="discovery-mode" class="input" bind:value={scanConfig.discoveryMode}>
        <option value="default">Default</option>
        <option value="skip">Skip (-Pn)</option>
        <option value="ping_only">Ping Only (-sn)</option>
        <option value="custom">Custom</option>
      </select>
    </div>

    {#if isCustom}
      <div class="probes-section">
        <span class="label">Probe Types</span>
        <div class="probes-grid">
          {#each probes as probe}
            <div class="probe-row">
              <label class="probe-check">
                <input
                  type="checkbox"
                  checked={scanConfig.discoveryMethods.includes(probe.id)}
                  onchange={() => toggleMethod(probe.id)}
                />
                <span class="probe-label">{probe.label}</span>
              </label>
              {#if probe.hasPorts && scanConfig.discoveryMethods.includes(probe.id)}
                <input
                  type="text"
                  class="input port-input"
                  placeholder={portBindings[probe.id].placeholder}
                  value={portBindings[probe.id].get()}
                  oninput={(e) => portBindings[probe.id].set((e.target as HTMLInputElement).value)}
                />
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</Collapsible>

<style>
  .discovery {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    max-width: 200px;
  }

  .label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .input {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 13px;
    width: 100%;
  }

  .input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .probes-section {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .probes-grid {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .probe-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }

  .probe-check {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    cursor: pointer;
    user-select: none;
    min-width: 200px;
  }

  .probe-label {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .port-input {
    max-width: 120px;
  }
</style>
