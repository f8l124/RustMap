summary = "Deep parse of SNMP sysDescr for OS and device model"
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
    return nil, 0 -- longer forms not supported
end

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- sysDescr.0 = 1.3.6.1.2.1.1.1.0
    local oid_bytes = "\x2B\x06\x01\x02\x01\x01\x01\x00"
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

    -- Extract OctetString value (last 0x04 tag) with BER multi-byte length
    local descr = nil
    local i = 1
    while i <= #data - 2 do
        if data:byte(i) == 0x04 then
            local vlen, consumed = decode_ber_length(data, i + 1)
            if vlen and i + consumed + vlen <= #data then
                descr = data:sub(i + 1 + consumed, i + consumed + vlen)
            end
        end
        i = i + 1
    end

    if not descr or #descr == 0 then
        return nil
    end

    local result = {"sysDescr: " .. descr}

    -- Parse for known patterns
    if descr:match("[Ll]inux") then
        result[#result + 1] = "OS: Linux"
        local kernel = descr:match("(%d+%.%d+%.%d+[%-%w%.]*)")
        if kernel then
            result[#result + 1] = "Kernel: " .. kernel
        end
    elseif descr:match("[Ww]indows") then
        result[#result + 1] = "OS: Windows"
    elseif descr:match("[Cc]isco") then
        result[#result + 1] = "Vendor: Cisco"
        local ios_ver = descr:match("Version ([%d%.%(%)%w]+)")
        if ios_ver then
            result[#result + 1] = "IOS: " .. ios_ver
        end
    elseif descr:match("[Jj]uniper") or descr:match("JUNOS") then
        result[#result + 1] = "Vendor: Juniper"
    end

    return table.concat(result, "; ")
end
