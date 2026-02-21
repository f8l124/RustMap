summary = "Brute-forces SNMP community strings"
categories = {"discovery", "intrusive"}
phases = {"portrule"}

portrule = shortport.port_or_service({161}, {"snmp"}, {"udp"}, nil)

function action(host, port)
    local communities = {
        "public", "private", "community", "manager",
        "admin", "snmp", "default", "test",
        "monitor", "read", "write", "secret",
        "cisco", "internal", "guest",
    }

    local found = {}

    for _, community in ipairs(communities) do
        local socket = nmap.new_udp_socket()
        socket:set_timeout(2000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto next_community
        end

        -- Build SNMP GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
        local community_bytes = community
        local oid = string.char(
            0x06, 0x08, -- OID type, length 8
            0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 -- 1.3.6.1.2.1.1.1.0
        )
        local varbind = string.char(0x30, #oid + 2) .. oid .. string.char(0x05, 0x00) -- NULL value
        local varbind_list = string.char(0x30, #varbind) .. varbind

        local pdu = string.char(0xA0) .. -- GetRequest PDU
            encode_length(
                4 + -- request ID
                3 + -- error status
                3 + -- error index
                #varbind_list
            ) ..
            string.char(0x02, 0x01, 0x01) .. -- request ID = 1
            string.char(0x02, 0x01, 0x00) .. -- error status = 0
            string.char(0x02, 0x01, 0x00) .. -- error index = 0
            varbind_list

        local message = string.char(0x02, 0x01, 0x00) .. -- version: SNMPv1
            string.char(0x04, #community_bytes) .. community_bytes ..
            pdu

        local packet = string.char(0x30) .. encode_length(#message) .. message

        status, err = socket:send(packet)
        if not status then
            socket:close()
            goto next_community
        end

        local ok, data = socket:receive()
        socket:close()

        if ok and #data > 10 then
            -- Check for valid SNMP response (starts with 0x30 and contains GetResponse 0xA2)
            if string.byte(data, 1) == 0x30 then
                local has_response = false
                for i = 1, math.min(#data, 30) do
                    if string.byte(data, i) == 0xA2 then
                        has_response = true
                        break
                    end
                end
                if has_response then
                    -- Extract sysDescr value if possible
                    local desc = extract_string_value(data)
                    if desc and #desc > 0 then
                        found[#found + 1] = community .. " (sysDescr: " .. desc:sub(1, 60) .. ")"
                    else
                        found[#found + 1] = community
                    end
                end
            end
        end

        ::next_community::
    end

    if #found == 0 then
        return nil
    end

    return "Valid community strings: " .. table.concat(found, ", ")
end

function encode_length(len)
    if len < 0x80 then
        return string.char(len)
    elseif len < 0x100 then
        return string.char(0x81, len)
    else
        return string.char(0x82, math.floor(len / 256), len % 256)
    end
end

function extract_string_value(data)
    -- Look for an OCTET STRING (0x04) after the OID in the response
    for i = 1, #data - 2 do
        if string.byte(data, i) == 0x04 and i > 20 then
            local slen = string.byte(data, i + 1)
            if slen and slen > 0 and slen < 200 and i + 1 + slen <= #data then
                return data:sub(i + 2, i + 1 + slen)
            end
        end
    end
    return nil
end
