summary = "Queries SNMP sysDescr, sysName, sysLocation (community 'public')"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = function(host, port)
    return port.number == 161 and port.protocol == "udp"
end

-- Decode a BER length field starting at position pos.
-- Returns (length, bytes_consumed) or (nil, 0) on failure.
local function decode_ber_length(data, pos)
    if pos > #data then return nil, 0 end
    local b = data:byte(pos)
    if not b then return nil, 0 end
    if b < 0x80 then
        return b, 1
    elseif b == 0x81 then
        if pos + 1 > #data then return nil, 0 end
        return data:byte(pos + 1), 2
    elseif b == 0x82 then
        if pos + 2 > #data then return nil, 0 end
        return data:byte(pos + 1) * 256 + data:byte(pos + 2), 3
    end
    return nil, 0 -- longer forms not supported
end

function action(host, port)
    -- Query sysDescr.0 (1.3.6.1.2.1.1.1.0)
    local oids = {
        {"\x2B\x06\x01\x02\x01\x01\x01\x00", "sysDescr"},
        {"\x2B\x06\x01\x02\x01\x01\x05\x00", "sysName"},
        {"\x2B\x06\x01\x02\x01\x01\x06\x00", "sysLocation"},
    }

    local result = {}

    for _, entry in ipairs(oids) do
        local oid_bytes, oid_name = entry[1], entry[2]
        local value = snmp_get(host, port, oid_bytes)
        if value and #value > 0 then
            result[#result + 1] = oid_name .. ": " .. value
        end
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end

function snmp_get(host, port, oid_bytes)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Build SNMPv1 GetRequest
    local community = "public"

    -- Variable binding: SEQUENCE { OID, NULL }
    local varbind = "\x30" .. string.char(#oid_bytes + 4)
        .. "\x06" .. string.char(#oid_bytes) .. oid_bytes
        .. "\x05\x00" -- NULL

    -- Variable binding list: SEQUENCE { varbind }
    local varbind_list = "\x30" .. string.char(#varbind) .. varbind

    -- PDU: GetRequest (0xA0)
    local pdu_body = "\x02\x01\x01" -- request-id: 1
        .. "\x02\x01\x00"           -- error-status: 0
        .. "\x02\x01\x00"           -- error-index: 0
        .. varbind_list

    local pdu = "\xA0" .. string.char(#pdu_body) .. pdu_body

    -- SNMP message: SEQUENCE { version, community, pdu }
    local msg_body = "\x02\x01\x00" -- version: SNMPv1 (0)
        .. "\x04" .. string.char(#community) .. community
        .. pdu

    local snmp_msg = "\x30" .. string.char(#msg_body) .. msg_body

    status, err = socket:send(snmp_msg)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 10 then
        return nil
    end

    -- Extract the value from the response
    -- Look for OctetString (0x04) followed by BER length and value
    -- Simple extraction: find the last 0x04 tag in the response
    local value = nil
    local i = 1
    while i <= #data - 2 do
        local tag = data:byte(i)
        if tag == 0x04 then
            local vlen, consumed = decode_ber_length(data, i + 1)
            if vlen and i + consumed + vlen <= #data then
                value = data:sub(i + 1 + consumed, i + consumed + vlen)
            end
        end
        i = i + 1
    end

    return value
end
