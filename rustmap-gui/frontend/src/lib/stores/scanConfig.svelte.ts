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
  scriptEnabled = $state(false);
  scripts = $state<string[]>([]);
  scriptArgs = $state("");
  customScriptPaths = $state<string[]>([]);
  geoipEnabled = $state(false);

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
      script_enabled: this.scriptEnabled,
      scripts: this.scripts,
      script_args: this.scriptArgs.trim() || null,
      custom_script_paths: this.customScriptPaths,
      geoip_enabled: this.geoipEnabled,
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
    this.scriptEnabled = false;
    this.scripts = [];
    this.scriptArgs = "";
    this.customScriptPaths = [];
    this.geoipEnabled = false;
  }

  loadFromConfig(config: GuiScanConfig) {
    this.targets = config.targets.join(", ");
    this.ports = config.ports ?? "";
    this.scanType = config.scan_type;
    this.timing = config.timing;
    this.serviceDetection = config.service_detection;
    this.osDetection = config.os_detection;
    this.discoveryMode = config.discovery_mode;
    this.discoveryMethods = config.discovery_methods;
    this.tcpSynPorts = config.tcp_syn_ports ?? "";
    this.tcpAckPorts = config.tcp_ack_ports ?? "";
    this.udpPingPorts = config.udp_ping_ports ?? "";
    this.httpPorts = config.http_ports ?? "";
    this.httpsPorts = config.https_ports ?? "";
    this.timeoutMs = config.timeout_ms;
    this.concurrency = config.concurrency;
    this.maxHostgroup = config.max_hostgroup;
    this.hostTimeoutMs = config.host_timeout_ms;
    this.minRate = config.min_rate;
    this.maxRate = config.max_rate;
    this.randomizePorts = config.randomize_ports;
    this.sourcePort = config.source_port;
    this.fragmentPackets = config.fragment_packets;
    this.traceroute = config.traceroute;
    this.versionIntensity = config.version_intensity;
    this.scanDelayMs = config.scan_delay_ms;
    this.mtuDiscovery = config.mtu_discovery;
    this.verbose = config.verbose;
    this.minHostgroup = config.min_hostgroup;
    this.maxScanDelayMs = config.max_scan_delay_ms;
    this.probeTimeoutMs = config.probe_timeout_ms;
    this.quicProbing = config.quic_probing;
    this.proxyUrl = config.proxy_url ?? "";
    this.decoys = config.decoys ?? "";
    this.preResolvedUp = config.pre_resolved_up ?? "";
    this.payloadType = config.payload_type;
    this.payloadValue = config.payload_value ?? "";
    this.scriptEnabled = config.script_enabled;
    this.scripts = config.scripts;
    this.scriptArgs = config.script_args ?? "";
    this.customScriptPaths = config.custom_script_paths;
    this.geoipEnabled = config.geoip_enabled;
  }
}

export const scanConfig = new ScanConfigStore();
