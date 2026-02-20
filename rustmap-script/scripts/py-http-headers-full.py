#!/usr/bin/env python3
# summary = "Full HTTP header dump with analysis"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Connects to an HTTP server and dumps all response headers with security analysis.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import socket
import sys


def main():
    data = json.load(sys.stdin)
    host = data["host"]
    port = data.get("port")

    if not port:
        json.dump(None, sys.stdout)
        return

    port_number = port["number"]
    service = (port.get("service") or {})
    service_name = service.get("name", "") if isinstance(service, dict) else ""

    if port_number not in (80, 443, 8080, 8443) and service_name not in ("http", "https"):
        json.dump(None, sys.stdout)
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host["ip"], port_number))

        request = f"GET / HTTP/1.1\r\nHost: {host['ip']}\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()

        text = response.decode(errors="ignore")
        header_end = text.find("\r\n\r\n")
        if header_end == -1:
            json.dump(None, sys.stdout)
            return

        header_block = text[:header_end]
        lines = header_block.split("\r\n")

        result_parts = []

        # Status line
        if lines:
            result_parts.append(lines[0])

        # All headers
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                headers[key.lower()] = value
                result_parts.append(f"  {key}: {value}")

        # Security analysis
        notes = []
        if "server" in headers:
            notes.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            notes.append(f"Powered-By: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            notes.append(f"ASP.NET: {headers['x-aspnet-version']}")

        if notes:
            result_parts.append("Info: " + "; ".join(notes))

        json.dump({"output": "\n".join(result_parts)}, sys.stdout)

    except Exception:
        json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
