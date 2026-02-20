#!/usr/bin/env python3
# summary = "Grabs SSH version string"
# categories = ["default", "safe", "version"]
# phases = ["portrule"]

"""
Connects to an SSH server and reads the version banner.
This is the Python equivalent of ssh-hostkey.lua's version detection.

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
    service = port.get("service") or ""
    if port_number != 22 and service != "ssh":
        json.dump(None, sys.stdout)
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host["ip"], port_number))
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()

        if banner.startswith("SSH-"):
            json.dump({"output": banner}, sys.stdout)
            return

    except Exception:
        pass

    json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
