#!/usr/bin/env python3
# summary = "Detects web technologies from HTTP headers and HTML"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Analyzes HTTP response headers and HTML content to identify web technologies,
frameworks, and server software.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import re
import socket
import sys


HEADER_SIGNATURES = {
    "x-powered-by": lambda v: v,
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-drupal-cache": lambda _: "Drupal",
    "x-generator": lambda v: v,
    "x-shopify-stage": lambda _: "Shopify",
    "x-wix-request-id": lambda _: "Wix",
    "x-litespeed-cache": lambda _: "LiteSpeed Cache",
    "x-varnish": lambda _: "Varnish",
    "x-cache": lambda v: f"CDN Cache ({v})",
}

HTML_PATTERNS = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', lambda m: m),
    (r'wp-content/', lambda _: "WordPress"),
    (r'/sites/default/files/', lambda _: "Drupal"),
    (r'Joomla!', lambda _: "Joomla"),
    (r'js/mage/', lambda _: "Magento"),
    (r'cdn\.shopify\.com', lambda _: "Shopify"),
    (r'_next/static/', lambda _: "Next.js"),
    (r'/__nuxt/', lambda _: "Nuxt.js"),
    (r'ng-version=["\'](\d+[^"\']*)["\']', lambda m: f"Angular {m}"),
    (r'react', lambda _: "React (suspected)"),
    (r'jquery[.-](\d+\.\d+\.\d+)', lambda m: f"jQuery {m}"),
    (r'bootstrap[.-](\d+\.\d+\.\d+)', lambda m: f"Bootstrap {m}"),
    (r'vue\.js', lambda _: "Vue.js"),
]


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

        header_block = text[:header_end]
        body = text[header_end + 4:]
        techs = set()

        # Parse headers
        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        # Check header signatures
        server = headers.get("server", "")
        if server:
            techs.add(f"Server: {server}")

        for hdr, extract in HEADER_SIGNATURES.items():
            if hdr in headers:
                techs.add(extract(headers[hdr]))

        # Check HTML patterns
        lower_body = body.lower()
        for pattern, extract in HTML_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                groups = match.groups()
                if groups:
                    techs.add(extract(groups[0]))
                else:
                    techs.add(extract(None))

        if not techs:
            json.dump(None, sys.stdout)
            return

        sorted_techs = sorted(techs)
        json.dump({"output": "Technologies: " + ", ".join(sorted_techs)}, sys.stdout)

    except Exception:
        json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
