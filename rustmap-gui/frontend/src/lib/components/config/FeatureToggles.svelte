<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import Toggle from "../shared/Toggle.svelte";
</script>

<div class="toggles">
  <Toggle
    label="Service Detection (-sV)"
    bind:checked={scanConfig.serviceDetection}
  />
  <Toggle
    label="OS Detection (-O)"
    bind:checked={scanConfig.osDetection}
  />
  <Toggle
    label="Traceroute (--traceroute)"
    bind:checked={scanConfig.traceroute}
  />
  <Toggle
    label="Randomize Ports (-r)"
    bind:checked={scanConfig.randomizePorts}
  />
  <Toggle
    label="MTU Discovery"
    bind:checked={scanConfig.mtuDiscovery}
  />
  <Toggle
    label="Verbose (-v)"
    bind:checked={scanConfig.verbose}
  />
  <Toggle
    label="QUIC Probing"
    bind:checked={scanConfig.quicProbing}
  />
  <Toggle
    label="GeoIP Tagging (--geoip)"
    bind:checked={scanConfig.geoipEnabled}
  />
  <Toggle
    label="IPv6 Only (-6)"
    bind:checked={scanConfig.ipv6Only}
  />
</div>

<style>
  .toggles {
    display: flex;
    gap: var(--space-md);
    flex-wrap: wrap;
  }
</style>
