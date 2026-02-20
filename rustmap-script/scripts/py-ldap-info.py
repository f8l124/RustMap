#!/usr/bin/env python3
# summary = "Extracts LDAP domain info via RootDSE query"
# categories = ["safe", "discovery"]
# phases = ["portrule"]

"""
Queries LDAP RootDSE for domain information using raw ASN.1/BER encoding.
Subprocess protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import socket
import struct
import sys


def ber_length(length):
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def ber_sequence(data):
    return b"\x30" + ber_length(len(data)) + data


def ber_octet_string(data):
    if isinstance(data, str):
        data = data.encode()
    return b"\x04" + ber_length(len(data)) + data


def ber_integer(val):
    return b"\x02\x01" + bytes([val & 0xFF])


def ber_boolean(val):
    return b"\x01\x01" + (b"\xFF" if val else b"\x00")


def ber_enumerated(val):
    return b"\x0A\x01" + bytes([val & 0xFF])


def build_search_request():
    """Build an LDAP SearchRequest for RootDSE."""
    # Filter: (objectClass=*) - present filter
    filt = b"\x87\x0BobjectClass"

    # Attributes
    attr_names = [
        "namingContexts",
        "defaultNamingContext",
        "dnsHostName",
        "serverName",
        "supportedLDAPVersion",
        "domainFunctionality",
        "forestFunctionality",
    ]
    attrs = b""
    for name in attr_names:
        attrs += ber_octet_string(name)
    attr_list = ber_sequence(attrs)

    # SearchRequest body
    body = (
        ber_octet_string(b"")  # baseObject
        + ber_enumerated(0)     # scope: base
        + ber_enumerated(0)     # derefAliases: never
        + ber_integer(0)        # sizeLimit
        + ber_integer(0)        # timeLimit
        + ber_boolean(False)    # typesOnly
        + filt
        + attr_list
    )

    # APPLICATION 3
    search_req = b"\x63" + ber_length(len(body)) + body

    # LDAPMessage
    msg = ber_integer(1) + search_req
    return ber_sequence(msg)


def decode_ber_length(data, pos):
    """Decode a BER length field with multi-byte support.

    If the high bit of the first byte is set, the lower 7 bits indicate
    how many subsequent bytes encode the length (BER long form).
    Returns (length, bytes_consumed) or (None, 0) on error.
    """
    if pos >= len(data):
        return None, 0
    b = data[pos]
    if b < 0x80:
        # Short form: length encoded in single byte
        return b, 1
    else:
        # Long form: lower 7 bits = number of subsequent length bytes
        num_bytes = b & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            # Indefinite length (0) or unreasonably large
            return None, 0
        if pos + 1 + num_bytes > len(data):
            return None, 0
        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[pos + 1 + i]
        return length, 1 + num_bytes


def parse_ber_strings(data, start=0):
    """Extract readable strings from BER-encoded data."""
    strings = []
    i = start
    while i < len(data) - 1:
        tag = data[i]
        if tag == 0x04:  # OctetString
            length, consumed = decode_ber_length(data, i + 1)
            if length is not None and i + 1 + consumed + length <= len(data):
                val = data[i + 1 + consumed:i + 1 + consumed + length]
                try:
                    text = val.decode("utf-8")
                    if text.isprintable() or text.replace(" ", "").isalnum():
                        strings.append(text)
                except (UnicodeDecodeError, ValueError):
                    pass
                i += 1 + consumed + length
                continue
        i += 1
    return strings


def main():
    data = json.load(sys.stdin)
    host = data["host"]
    port_info = data.get("port")

    if not port_info:
        json.dump(None, sys.stdout)
        return

    port_number = port_info["number"]
    service = (port_info.get("service") or {})
    service_name = service.get("name", "") if isinstance(service, dict) else ""

    if port_number not in (389, 636) and service_name not in ("ldap", "ldaps"):
        json.dump(None, sys.stdout)
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host["ip"], port_number))

        request = build_search_request()
        s.sendall(request)

        # Read up to 4096 bytes per chunk to capture full RootDSE responses.
        # Cap total at 8192 bytes to prevent unbounded accumulation.
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
            except socket.timeout:
                break
        s.close()

        if len(response) < 10:
            json.dump(None, sys.stdout)
            return

        strings = parse_ber_strings(response)

        # Filter for interesting values
        result_parts = []
        attr_names = {
            "namingContexts", "defaultNamingContext", "dnsHostName",
            "serverName", "supportedLDAPVersion",
            "domainFunctionality", "forestFunctionality",
        }

        current_attr = None
        for s_val in strings:
            if s_val in attr_names:
                current_attr = s_val
            elif current_attr and len(s_val) > 0:
                result_parts.append(f"{current_attr}: {s_val}")
                current_attr = None

        if not result_parts and strings:
            result_parts.append("LDAP RootDSE accessible")
            for s_val in strings[:5]:
                if len(s_val) > 2:
                    result_parts.append(f"  {s_val}")

        if result_parts:
            json.dump({"output": "\n".join(result_parts)}, sys.stdout)
        else:
            json.dump(None, sys.stdout)

    except Exception:
        json.dump(None, sys.stdout)


if __name__ == "__main__":
    main()
