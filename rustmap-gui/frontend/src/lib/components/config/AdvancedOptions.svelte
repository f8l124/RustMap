<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Collapsible from "../shared/Collapsible.svelte";
  import Toggle from "../shared/Toggle.svelte";
</script>

<Collapsible title="Advanced Options">
  <div class="grid">
    <div class="field">
      <label for="concurrency" class="label">Concurrency</label>
      <input
        id="concurrency"
        type="number"
        class="input"
        min="1"
        max="10000"
        bind:value={scanConfig.concurrency}
      />
    </div>
    <div class="field">
      <label for="timeout" class="label">Timeout (ms)</label>
      <input
        id="timeout"
        type="number"
        class="input"
        min="100"
        bind:value={scanConfig.timeoutMs}
      />
    </div>
    <div class="field">
      <label for="hostgroup" class="label">Max Hostgroup</label>
      <input
        id="hostgroup"
        type="number"
        class="input"
        min="1"
        max="65535"
        bind:value={scanConfig.maxHostgroup}
      />
    </div>
    <div class="field">
      <label for="host-timeout" class="label">Host Timeout (ms)</label>
      <input
        id="host-timeout"
        type="number"
        class="input"
        min="0"
        bind:value={scanConfig.hostTimeoutMs}
      />
    </div>
    <div class="field">
      <label for="min-rate" class="label">Min Rate (pkt/s)</label>
      <input
        id="min-rate"
        type="number"
        class="input"
        min="0"
        placeholder="—"
        bind:value={scanConfig.minRate}
      />
    </div>
    <div class="field">
      <label for="max-rate" class="label">Max Rate (pkt/s)</label>
      <input
        id="max-rate"
        type="number"
        class="input"
        min="0"
        placeholder="—"
        bind:value={scanConfig.maxRate}
      />
    </div>
    <div class="field">
      <label for="source-port" class="label">Source Port</label>
      <input
        id="source-port"
        type="number"
        class="input"
        min="0"
        max="65535"
        placeholder="—"
        bind:value={scanConfig.sourcePort}
      />
    </div>
    <div class="field">
      <label for="version-intensity" class="label">Version Intensity</label>
      <input
        id="version-intensity"
        type="number"
        class="input"
        min="0"
        max="9"
        bind:value={scanConfig.versionIntensity}
      />
    </div>
    <div class="field">
      <label for="scan-delay" class="label">Scan Delay (ms)</label>
      <input
        id="scan-delay"
        type="number"
        class="input"
        min="0"
        bind:value={scanConfig.scanDelayMs}
      />
    </div>
    <div class="field">
      <label for="min-hostgroup" class="label">Min Hostgroup</label>
      <input
        id="min-hostgroup"
        type="number"
        class="input"
        min="1"
        max="65535"
        bind:value={scanConfig.minHostgroup}
      />
    </div>
    <div class="field">
      <label for="max-scan-delay" class="label">Max Scan Delay (ms)</label>
      <input
        id="max-scan-delay"
        type="number"
        class="input"
        min="0"
        bind:value={scanConfig.maxScanDelayMs}
      />
    </div>
    <div class="field">
      <label for="probe-timeout" class="label">Probe Timeout (ms)</label>
      <input
        id="probe-timeout"
        type="number"
        class="input"
        min="0"
        bind:value={scanConfig.probeTimeoutMs}
      />
    </div>
    <div class="field">
      <label for="ip-ttl" class="label">IP TTL</label>
      <input
        id="ip-ttl"
        type="number"
        class="input"
        min="1"
        max="255"
        placeholder="—"
        bind:value={scanConfig.ipTtl}
      />
    </div>
    <div class="field toggle-field">
      <Toggle
        label="Fragment Packets (-f)"
        bind:checked={scanConfig.fragmentPackets}
      />
    </div>
    <div class="field toggle-field">
      <Toggle
        label="Bad Checksum (--badsum)"
        bind:checked={scanConfig.badsum}
      />
    </div>
  </div>

  <div class="text-fields">
    <div class="text-field">
      <label for="proxy-url" class="label">SOCKS5 Proxy</label>
      <input
        id="proxy-url"
        type="text"
        class="input"
        placeholder="socks5://host:port"
        bind:value={scanConfig.proxyUrl}
      />
    </div>
    <div class="text-field">
      <label for="decoys" class="label">Decoy IPs</label>
      <input
        id="decoys"
        type="text"
        class="input"
        placeholder="10.0.0.1, 10.0.0.2"
        bind:value={scanConfig.decoys}
      />
    </div>
    <div class="text-field">
      <label for="pre-resolved-up" class="label">Pre-resolved Up Hosts</label>
      <input
        id="pre-resolved-up"
        type="text"
        class="input"
        placeholder="192.168.1.1, 192.168.1.2"
        bind:value={scanConfig.preResolvedUp}
      />
    </div>
    <div class="text-field">
      <label for="spoof-mac" class="label">Spoof MAC (--spoof-mac)</label>
      <input
        id="spoof-mac"
        type="text"
        class="input"
        placeholder="AA:BB:CC:DD:EE:FF or random"
        bind:value={scanConfig.spoofMac}
      />
    </div>
  </div>

  <div class="text-fields">
    <div class="text-field">
      <label for="payload-type" class="label">Custom Payload</label>
      <select id="payload-type" class="input" bind:value={scanConfig.payloadType}>
        <option value="none">None</option>
        <option value="hex">Hex Bytes</option>
        <option value="string">ASCII String</option>
        <option value="length">Random Length</option>
      </select>
    </div>
    {#if scanConfig.payloadType !== "none"}
      <div class="text-field">
        <label for="payload-value" class="label">
          {scanConfig.payloadType === "hex" ? "Hex Data" : scanConfig.payloadType === "string" ? "String Data" : "Byte Count"}
        </label>
        <input
          id="payload-value"
          type="text"
          class="input"
          placeholder={scanConfig.payloadType === "hex" ? "deadbeef" : scanConfig.payloadType === "string" ? "HELLO" : "32"}
          bind:value={scanConfig.payloadValue}
        />
      </div>
    {/if}
  </div>
</Collapsible>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: var(--space-sm);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
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

  .toggle-field {
    display: flex;
    align-items: flex-end;
    padding-bottom: var(--space-xs);
  }

  .text-fields {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin-top: var(--space-sm);
  }

  .text-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
</style>
