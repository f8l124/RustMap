summary = "Walks SNMP ifTable for interface list (ifDescr, ifType, ifSpeed)"
categories = {"safe", "discovery"}
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
    return nil, 0
end

-- Encode an OID sub-identifier using BER variable-length encoding.
-- Values < 128 use a single byte; >= 128 use multi-byte with high bit continuation.
local function encode_oid_subid(val)
    if val < 128 then
        return string.char(val)
    end
    -- Multi-byte: split into 7-bit groups with continuation bits
    local bytes = {}
    bytes[1] = string.char(val % 128)
    val = math.floor(val / 128)
    while val > 0 do
        table.insert(bytes, 1, string.char(128 + (val % 128)))
        val = math.floor(val / 128)
    end
    return table.concat(bytes)
end

function action(host, port)
    -- Query ifNumber.0 (1.3.6.1.2.1.2.1.0) first
    local ifnum = snmp_get_value(host, port, "\x2B\x06\x01\x02\x01\x02\x01\x00")
    if not ifnum then
        return nil
    end

    -- Then walk ifDescr (1.3.6.1.2.1.2.2.1.2) for each interface
    local base_oid = "\x2B\x06\x01\x02\x01\x02\x02\x01\x02"
    local interfaces = {}
    for idx = 1, 32 do -- max 32 interfaces
        local oid = base_oid .. encode_oid_subid(idx)
        local name = snmp_get_value(host, port, oid)
        if name and #name > 0 then
            interfaces[#interfaces + 1] = name
        else
            break
        end
    end

    if #interfaces == 0 then
        return nil
    end

    return string.format("Interfaces (%s): %s", ifnum, table.concat(interfaces, ", "))
end

function snmp_get_value(host, port, oid_bytes)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(2000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local community = "public"
    local varbind = "\x30" .. string.char(#oid_bytes + 4)
        .. "\x06" .. string.char(#oid_bytes) .. oid_bytes
        .. "\x05\x00"
    local varbind_list = "\x30" .. string.char(#varbind) .. varbind
    local pdu_body = "\x02\x01\x01\x02\x01\x00\x02\x01\x00" .. varbind_list
    local pdu = "\xA0" .. string.char(#pdu_body) .. pdu_body
    local msg_body = "\x02\x01\x00\x04" .. string.char(#community) .. community .. pdu
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

    -- Extract value: look for OctetString (0x04) or Integer (0x02) after the OID
    local value = nil
    local i = 1
    while i <= #data - 2 do
        local tag = data:byte(i)
        if tag == 0x04 then
            local vlen, consumed = decode_ber_length(data, i + 1)
            if vlen and i + consumed + vlen <= #data then
                value = data:sub(i + 1 + consumed, i + consumed + vlen)
            end
        elseif tag == 0x02 and i > #data / 2 then
            -- Integer in second half of response (likely the value, not request-id)
            local vlen, consumed = decode_ber_length(data, i + 1)
            if vlen and vlen <= 4 and i + consumed + vlen <= #data then
                local num = 0
                for j = 0, vlen - 1 do
                    num = num * 256 + data:byte(i + 1 + consumed + j)
                end
                value = tostring(num)
            end
        end
        i = i + 1
    end

    return value
end
