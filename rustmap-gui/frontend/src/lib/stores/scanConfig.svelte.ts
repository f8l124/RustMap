import type { GuiScanConfig } from "../types";

class ScanConfigStore {
  targets = $state("");
  ports = $state("");
  scanType = $state("T");
  timing = $state(3);
  serviceDetection = $state(false);
  osDetection = $state(false);
  discoveryMode = $state("default");
  discoveryMethods = $state<string[]>([]);
  tcpSynPorts = $state("");
  tcpAckPorts = $state("");
  udpPingPorts = $state("");
  httpPorts = $state("");
  httpsPorts = $state("");
  timeoutMs = $state(0);
  concurrency = $state(0);
  maxHostgroup = $state(256);
  hostTimeoutMs = $state(0);
  minRate = $state<number | null>(null);
  maxRate = $state<number | null>(null);
  randomizePorts = $state(false);
  sourcePort = $state<number | null>(null);
  fragmentPackets = $state(false);
  traceroute = $state(false);
  versionIntensity = $state(7);
  scanDelayMs = $state(0);
  mtuDiscovery = $state(false);
  verbose = $state(false);
  minHostgroup = $state(1);
  maxScanDelayMs = $state(0);
  probeTimeoutMs = $state(0);
  quicProbing = $state(true);
  proxyUrl = $state("");
  decoys = $state("");
  preResolvedUp = $state("");
  payloadType = $state("none");
  payloadValue = $state("");

  get configValid(): boolean {
    return this.targets.trim().length > 0;
  }

  get config(): GuiScanConfig {
    const targetList = this.targets
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    return {
      targets: targetList,
      ports: this.ports.trim() || null,
      scan_type: this.scanType,
      timing: this.timing,
      service_detection: this.serviceDetection,
      os_detection: this.osDetection,
      discovery_mode: this.discoveryMode,
      discovery_methods: this.discoveryMethods,
      tcp_syn_ports: this.tcpSynPorts.trim() || null,
      tcp_ack_ports: this.tcpAckPorts.trim() || null,
      udp_ping_ports: this.udpPingPorts.trim() || null,
      http_ports: this.httpPorts.trim() || null,
      https_ports: this.httpsPorts.trim() || null,
      timeout_ms: this.timeoutMs,
      concurrency: this.concurrency,
      max_hostgroup: this.maxHostgroup,
      host_timeout_ms: this.hostTimeoutMs,
      min_rate: this.minRate,
      max_rate: this.maxRate,
      randomize_ports: this.randomizePorts,
      source_port: this.sourcePort,
      fragment_packets: this.fragmentPackets,
      traceroute: this.traceroute,
      version_intensity: this.versionIntensity,
      scan_delay_ms: this.scanDelayMs,
      mtu_discovery: this.mtuDiscovery,
      verbose: this.verbose,
      min_hostgroup: this.minHostgroup,
      max_scan_delay_ms: this.maxScanDelayMs,
      probe_timeout_ms: this.probeTimeoutMs,
      quic_probing: this.quicProbing,
      proxy_url: this.proxyUrl.trim() || null,
      decoys: this.decoys.trim() || null,
      pre_resolved_up: this.preResolvedUp.trim() || null,
      payload_type: this.payloadType,
      payload_value: this.payloadValue.trim() || null,
    };
  }

  reset() {
    this.targets = "";
    this.ports = "";
    this.scanType = "T";
    this.timing = 3;
    this.serviceDetection = false;
    this.osDetection = false;
    this.discoveryMode = "default";
    this.discoveryMethods = [];
    this.tcpSynPorts = "";
    this.tcpAckPorts = "";
    this.udpPingPorts = "";
    this.httpPorts = "";
    this.httpsPorts = "";
    this.timeoutMs = 0;
    this.concurrency = 0;
    this.maxHostgroup = 256;
    this.hostTimeoutMs = 0;
    this.minRate = null;
    this.maxRate = null;
    this.randomizePorts = false;
    this.sourcePort = null;
    this.fragmentPackets = false;
    this.traceroute = false;
    this.versionIntensity = 7;
    this.scanDelayMs = 0;
    this.mtuDiscovery = false;
    this.verbose = false;
    this.minHostgroup = 1;
    this.maxScanDelayMs = 0;
    this.probeTimeoutMs = 0;
    this.quicProbing = true;
    this.proxyUrl = "";
    this.decoys = "";
    this.preResolvedUp = "";
    this.payloadType = "none";
    this.payloadValue = "";
  }
}

export const scanConfig = new ScanConfigStore();
