export interface ScanTypeInfo {
  flag: string;
  label: string;
  description: string;
  requiresPrivilege: boolean;
}

export const SCAN_TYPES: ScanTypeInfo[] = [
  {
    flag: "T",
    label: "TCP Connect",
    description: "Full TCP connection scan (no privileges required)",
    requiresPrivilege: false,
  },
  {
    flag: "S",
    label: "TCP SYN",
    description: "Half-open SYN scan (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "U",
    label: "UDP",
    description: "UDP port scan (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "F",
    label: "TCP FIN",
    description: "FIN stealth scan (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "N",
    label: "TCP Null",
    description: "Null scan — no flags set (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "X",
    label: "TCP Xmas",
    description: "Xmas scan — FIN+PSH+URG (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "A",
    label: "TCP ACK",
    description: "ACK scan for firewall detection (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "W",
    label: "TCP Window",
    description: "Window scan — like ACK but checks window size (requires raw sockets)",
    requiresPrivilege: true,
  },
  {
    flag: "M",
    label: "TCP Maimon",
    description: "Maimon scan — FIN+ACK (requires raw sockets)",
    requiresPrivilege: true,
  },
];

export const TIMING_TEMPLATES = [
  { value: 0, label: "T0 — Paranoid", description: "5 min delay between probes" },
  { value: 1, label: "T1 — Sneaky", description: "15 sec delay between probes" },
  { value: 2, label: "T2 — Polite", description: "400ms delay between probes" },
  { value: 3, label: "T3 — Normal", description: "Default timing" },
  { value: 4, label: "T4 — Aggressive", description: "Fast, assumes reliable network" },
  { value: 5, label: "T5 — Insane", description: "Fastest, may miss results" },
];
