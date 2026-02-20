import type { PrivilegeInfo } from "../types";

class PrivilegesStore {
  info = $state<PrivilegeInfo>({ raw_socket: false, pcap: false });

  set(info: PrivilegeInfo) {
    this.info = info;
  }

  get hasRawSocket(): boolean {
    return this.info.raw_socket;
  }

  get hasPcap(): boolean {
    return this.info.pcap;
  }

  get isPrivileged(): boolean {
    return this.info.raw_socket || this.info.pcap;
  }
}

export const privileges = new PrivilegesStore();
