#!/usr/bin/env python3
# summary = "Crawls HTTP page and extracts all links"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Fetches an HTTP page and extracts all <a href> links, reporting
internal/external link counts and unique external domains.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import re
import socket
import sys
from urllib.parse import urlparse


def main():
    data = json.load(sys.stdin)
    host = data["host"]
    port_info = data.get("port")

    if not port_info:
        json.dump(None, sys.stdout)
        return

    port_number = port_info["number"]
    service = port_info.get("service") or {}
    service_name = service.get("name", "") if isinstance(service, dict) else ""

    if port_number not in (80, 443, 8080, 8443) and service_name not in ("http", "https"):
        json.dump(None, sys.stdout)
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host["ip"], port_number))

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host['ip']}\r\n"
            f"User-Agent: rustmap\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 1048576:
                    break
            except socket.timeout:
                break
        s.close()

        text = response.decode(errors="ignore")
        header_end = text.find("\r\n\r\n")
        if header_end == -1:
            json.dump(None, sys.stdout)
            return

        body = text[header_end + 4:]

        # Extract all href values
        hrefs = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if not hrefs:
            json.dump({"output": "No links found on page"}, sys.stdout)
            return

        internal = []
        external = []
        ext_domains = set()

        for href in hrefs:
            href = href.strip()
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            parsed = urlparse(href)
            if parsed.scheme in ("http", "https") and parsed.hostname:
                if parsed.hostname == host["ip"]:
                    internal.append(href)
                else:
                    external.append(href)
                    ext_domains.add(parsed.hostname)
            elif not parsed.scheme or href.startswith("/"):
                internal.append(href)
            else:
                external.append(href)
                if parsed.hostname:
                    ext_domains.add(parsed.hostname)

        parts = []
        parts.append(f"Links: {len(internal)} internal, {len(external)} external")
        if ext_domains:
            sorted_domains = sorted(ext_domains)[:10]
            parts.append("External domains: " + ", ".join(sorted_domains))
            if len(ext_domains) > 10:
                parts.append(f"  ... and {len(ext_domains) - 10} more")

        json.dump({"output": "\n".join(parts)}, sys.stdout)

    except Exception:
        json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
