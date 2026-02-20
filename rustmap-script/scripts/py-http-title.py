#!/usr/bin/env python3
# summary = "Shows the title of a web page (Python version)"
# categories = ["default", "safe", "discovery"]
# phases = ["portrule"]

"""
Connects to an HTTP server and extracts the <title> tag from the response.
This is the Python equivalent of http-title.lua.

Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import re
import socket
import ssl
import sys


def main():
    data = json.load(sys.stdin)
    host = data["host"]
    port = data.get("port")

    if not port:
        json.dump(None, sys.stdout)
        return

    port_number = port["number"]
    if port_number not in (80, 443, 8080, 8443):
        service = port.get("service") or ""
        if service not in ("http", "https"):
            json.dump(None, sys.stdout)
            return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host["ip"], port_number))

        if port_number in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host["ip"])

        request = f"GET / HTTP/1.1\r\nHost: {host['ip']}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())

        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                break
        s.close()

        text = response.decode(errors="ignore")
        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if match:
            title = " ".join(match.group(1).strip().split())
            json.dump({"output": f"Title: {title}"}, sys.stdout)
            return

    except Exception:
        pass

    json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
