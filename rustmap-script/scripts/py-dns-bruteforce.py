#!/usr/bin/env python3
# summary = "Brute-forces DNS subdomains using common wordlist"
# categories = ["discovery", "intrusive"]
# phases = ["prerule"]

"""
Brute-forces DNS subdomains for a target domain using a built-in wordlist.
Requires script argument 'dns-bruteforce.domain' to specify the target domain.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import socket
import struct
import sys

WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2",
    "admin", "api", "app", "dev", "staging", "test", "beta",
    "portal", "vpn", "remote", "gateway", "proxy",
    "cdn", "static", "assets", "media", "images", "img",
    "blog", "forum", "wiki", "docs", "support", "help",
    "git", "gitlab", "jenkins", "ci", "build",
    "db", "database", "sql", "mysql", "postgres",
    "monitor", "grafana", "prometheus", "nagios", "zabbix",
    "intranet", "internal", "corp", "office",
]


def build_dns_query(domain):
    """Build a DNS A record query packet."""
    # Transaction ID
    import random
    txid = struct.pack("!H", random.randint(1, 65535))

    # Flags: standard query, recursion desired
    flags = struct.pack("!H", 0x0100)
    # Questions: 1, Answers: 0, Authority: 0, Additional: 0
    counts = struct.pack("!HHHH", 1, 0, 0, 0)

    # QNAME
    qname = b""
    for label in domain.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"

    # QTYPE: A (1), QCLASS: IN (1)
    qtype = struct.pack("!HH", 1, 1)

    return txid + flags + counts + qname + qtype


def resolve_name(domain, dns_server="8.8.8.8"):
    """Resolve a domain name to IP addresses using DNS."""
    try:
        query = build_dns_query(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(query, (dns_server, 53))
        data, _ = s.recvfrom(4096)
        s.close()

        if len(data) < 12:
            return []

        # Parse header
        flags = struct.unpack("!H", data[2:4])[0]
        rcode = flags & 0x0F
        if rcode != 0:  # NXDOMAIN or other error
            return []

        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return []

        # Skip question section
        offset = 12
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            if label_len >= 0xC0:  # Pointer
                offset += 2
                break
            offset += 1 + label_len
        else:
            offset += 1  # null terminator
        offset += 4  # QTYPE + QCLASS

        # Parse answer records
        ips = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Name (possibly compressed)
            if data[offset] >= 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1

            if offset + 10 > len(data):
                break

            rtype = struct.unpack("!H", data[offset:offset + 2])[0]
            rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
            offset += 10

            if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
                ip = socket.inet_ntoa(data[offset:offset + 4])
                ips.append(ip)

            offset += rdlength

        return ips

    except Exception:
        return []


def main():
    data = json.load(sys.stdin)
    args = data.get("args", {})
    domain = args.get("dns-bruteforce.domain", "")

    if not domain:
        json.dump(None, sys.stdout)
        return

    dns_server = args.get("dns-bruteforce.dns", "8.8.8.8")

    found = []
    for subdomain in WORDLIST:
        fqdn = f"{subdomain}.{domain}"
        ips = resolve_name(fqdn, dns_server)
        if ips:
            found.append(f"{fqdn} -> {', '.join(ips)}")

    if not found:
        json.dump({"output": f"No subdomains found for {domain}"}, sys.stdout)
        return

    parts = [f"DNS bruteforce for {domain}: {len(found)} subdomains found"]
    for entry in found[:50]:  # Limit output
        parts.append(f"  {entry}")
    if len(found) > 50:
        parts.append(f"  ... and {len(found) - 50} more")

    json.dump({"output": "\n".join(parts)}, sys.stdout)


if __name__ == "__main__":
    main()
