import type { GuiScanConfig } from "../types";

class ScanConfigStore {
  targets = $state("");
  ports = $state("");
  scanType = $state("T");
  timing = $state(3);
  serviceDetection = $state(false);
  osDetection = $state(false);
  skipDiscovery = $state(false);
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
      skip_discovery: this.skipDiscovery,
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
    };
  }

  reset() {
    this.targets = "";
    this.ports = "";
    this.scanType = "T";
    this.timing = 3;
    this.serviceDetection = false;
    this.osDetection = false;
    this.skipDiscovery = false;
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
  }
}

export const scanConfig = new ScanConfigStore();
