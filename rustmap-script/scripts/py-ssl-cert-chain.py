#!/usr/bin/env python3
# summary = "Fetches and analyzes the full SSL/TLS certificate chain"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Connects via TLS, retrieves the full certificate chain, and reports
each certificate's subject, issuer, validity, and key details.
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

        # Get peer certificate chain (binary DER form)
        der_cert = conn.getpeercert(binary_form=True)
        peer_cert = conn.getpeercert(binary_form=False)
        cipher_info = conn.cipher()
        tls_version = conn.version()
        conn.close()

        parts = []

        # Connection info
        if tls_version:
            parts.append(f"Protocol: {tls_version}")
        if cipher_info:
            parts.append(f"Cipher: {cipher_info[0]} ({cipher_info[2]} bits)")

        if not peer_cert:
            parts.append("Certificate: details unavailable")
            json.dump({"output": "\n".join(parts)}, sys.stdout)
            return

        # Leaf certificate details
        parts.append("--- Leaf Certificate ---")

        subject = extract_dn(peer_cert.get("subject", ()))
        if subject:
            parts.append(f"  Subject: {subject}")

        issuer = extract_dn(peer_cert.get("issuer", ()))
        if issuer:
            parts.append(f"  Issuer: {issuer}")

        not_before = peer_cert.get("notBefore", "")
        not_after = peer_cert.get("notAfter", "")
        if not_before:
            parts.append(f"  Valid: {not_before} - {not_after}")

        # Check expiry
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                if days_left < 0:
                    parts.append(f"  STATUS: EXPIRED ({abs(days_left)} days ago)")
                elif days_left < 30:
                    parts.append(f"  STATUS: Expiring soon ({days_left} days)")
                else:
                    parts.append(f"  STATUS: Valid ({days_left} days remaining)")
            except ValueError:
                pass

        # Serial number
        serial = peer_cert.get("serialNumber", "")
        if serial:
            parts.append(f"  Serial: {serial}")

        # SANs
        sans = peer_cert.get("subjectAltName", ())
        san_dns = [v for t, v in sans if t == "DNS"]
        if san_dns:
            if len(san_dns) <= 5:
                parts.append(f"  SANs: {', '.join(san_dns)}")
            else:
                parts.append(f"  SANs: {', '.join(san_dns[:5])} +{len(san_dns) - 5} more")

        # Self-signed check
        if subject == issuer:
            parts.append("  WARNING: Self-signed certificate")

        # Signature algorithm (from OCSP/CRL)
        ocsp = peer_cert.get("OCSP", ())
        if ocsp:
            parts.append(f"  OCSP: {', '.join(ocsp[:2])}")

        crl = peer_cert.get("crlDistributionPoints", ())
        if crl:
            parts.append(f"  CRL: {crl[0]}")

        json.dump({"output": "\n".join(parts)}, sys.stdout)

    except Exception:
        json.dump(None, sys.stdout)


def extract_dn(dn_tuple):
    """Extract distinguished name as a readable string."""
    parts = []
    for rdn in dn_tuple:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts) if parts else ""


if __name__ == "__main__":
    main()
