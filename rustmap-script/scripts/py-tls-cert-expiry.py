#!/usr/bin/env python3
# summary = "Checks TLS certificate expiration and reports SANs"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Connects via TLS, checks certificate expiration date, and reports
Subject Alternative Names.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import socket
import ssl
import sys
from datetime import datetime, timezone


def main():
    data = json.load(sys.stdin)
    host = data["host"]
    port_info = data.get("port")

    if not port_info:
        json.dump(None, sys.stdout)
        return

    port_number = port_info["number"]

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        conn = context.wrap_socket(s, server_hostname=host["ip"])
        conn.connect((host["ip"], port_number))

        cert = conn.getpeercert(binary_form=False)
        der_cert = conn.getpeercert(binary_form=True)
        conn.close()

        if not cert:
            # If getpeercert returns empty dict (CERT_NONE mode), parse binary
            # In CERT_NONE mode, getpeercert(False) may return empty
            # Try with CERT_REQUIRED for cert details
            context2 = ssl.create_default_context()
            context2.check_hostname = False
            context2.verify_mode = ssl.CERT_NONE
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5)
            conn2 = context2.wrap_socket(s2, server_hostname=host["ip"])
            conn2.connect((host["ip"], port_number))
            # Get cipher and version info even without cert details
            cipher = conn2.cipher()
            version = conn2.version()
            conn2.close()

            parts = []
            if version:
                parts.append(f"TLS Version: {version}")
            if cipher:
                parts.append(f"Cipher: {cipher[0]}")
            parts.append("Certificate details unavailable (self-signed or CERT_NONE)")
            json.dump({"output": "\n".join(parts)}, sys.stdout)
            return

        parts = []

        # Expiration check
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days

                if days_left < 0:
                    parts.append(f"EXPIRED {abs(days_left)} days ago!")
                elif days_left < 30:
                    parts.append(f"WARNING: expires in {days_left} days ({not_after})")
                else:
                    parts.append(f"Expires: {not_after} ({days_left} days)")
            except ValueError:
                parts.append(f"Expires: {not_after}")

        # Not Before
        not_before = cert.get("notBefore", "")
        if not_before:
            parts.append(f"Valid from: {not_before}")

        # Subject
        subject = cert.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    parts.append(f"CN: {attr_value}")

        # Issuer
        issuer = cert.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type == "organizationName":
                    parts.append(f"Issuer: {attr_value}")

        # SANs
        sans = cert.get("subjectAltName", ())
        san_list = [value for san_type, value in sans if san_type == "DNS"]
        if san_list:
            if len(san_list) <= 5:
                parts.append(f"SANs: {', '.join(san_list)}")
            else:
                parts.append(f"SANs: {', '.join(san_list[:5])} ... +{len(san_list) - 5} more")

        json.dump({"output": "\n".join(parts)}, sys.stdout)

    except Exception as e:
        json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
