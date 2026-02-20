import type { HostScanResult, HostStatus, Port, PortState } from "../types";
import { scanState } from "./scanState.svelte";
import { scanConfig } from "./scanConfig.svelte";

class ResultFilterStore {
  searchQuery = $state("");
  portFilter = $state("");
  stateFilters = $state<Set<PortState>>(new Set());
  statusFilters = $state<Set<HostStatus>>(new Set());

  get hasActiveFilters(): boolean {
    return (
      this.searchQuery.trim().length > 0 ||
      this.portFilter.trim().length > 0 ||
      this.stateFilters.size > 0 ||
      this.statusFilters.size > 0
    );
  }

  get filteredHosts(): HostScanResult[] {
    let hosts = scanState.hostResults;

    // Host status filter
    if (this.statusFilters.size > 0) {
      hosts = hosts.filter((h) => this.statusFilters.has(h.host_status));
    }

    // IP/hostname text search
    const query = this.searchQuery.trim().toLowerCase();
    if (query) {
      hosts = hosts.filter(
        (h) =>
          h.host.ip.toLowerCase().includes(query) ||
          (h.host.hostname?.toLowerCase().includes(query) ?? false),
      );
    }

    // Filter hosts by whether they have any visible ports
    hosts = hosts.filter((h) => {
      // Hosts with no ports pass through (e.g., ping-only results)
      if (h.ports.length === 0) return true;
      return this.filteredPorts(h).length > 0;
    });

    return hosts;
  }

  get matchCount(): number {
    return this.filteredHosts.length;
  }

  get totalCount(): number {
    return scanState.hostResults.length;
  }

  get hasUserSpecifiedPorts(): boolean {
    return scanConfig.ports.trim().length > 0;
  }

  filteredPorts(host: HostScanResult): Port[] {
    let ports = host.ports;

    // Port number filter from the filter bar
    const portSet = this.parsePortFilter();
    if (portSet) {
      ports = ports.filter((p) => portSet.has(p.number));
    }

    // Port state filter
    if (this.stateFilters.size > 0) {
      // Explicit state filters active — show only matching states
      ports = ports.filter((p) => this.stateFilters.has(p.state));
    } else if (!this.hasUserSpecifiedPorts) {
      // No state filters AND user didn't specify explicit ports —
      // default to showing only open ports
      ports = ports.filter(
        (p) => p.state === "open" || p.state === "open|filtered",
      );
    }
    // If user specified explicit ports and no state filter — show all states

    return ports;
  }

  toggleStateFilter(state: PortState) {
    const next = new Set(this.stateFilters);
    if (next.has(state)) {
      next.delete(state);
    } else {
      next.add(state);
    }
    this.stateFilters = next;
  }

  toggleStatusFilter(status: HostStatus) {
    const next = new Set(this.statusFilters);
    if (next.has(status)) {
      next.delete(status);
    } else {
      next.add(status);
    }
    this.statusFilters = next;
  }

  reset() {
    this.searchQuery = "";
    this.portFilter = "";
    this.stateFilters = new Set();
    this.statusFilters = new Set();
  }

  private parsePortFilter(): Set<number> | null {
    const raw = this.portFilter.trim();
    if (!raw) return null;

    const ports = new Set<number>();
    for (const part of raw.split(",")) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      if (trimmed.includes("-")) {
        const [startStr, endStr] = trimmed.split("-");
        const start = parseInt(startStr!, 10);
        const end = parseInt(endStr!, 10);
        if (!isNaN(start) && !isNaN(end)) {
          for (let p = start; p <= end && p <= 65535; p++) {
            ports.add(p);
          }
        }
      } else {
        const num = parseInt(trimmed, 10);
        if (!isNaN(num)) {
          ports.add(num);
        }
      }
    }

    return ports.size > 0 ? ports : null;
  }
}

export const resultFilter = new ResultFilterStore();
