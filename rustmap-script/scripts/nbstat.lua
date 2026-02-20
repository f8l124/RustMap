summary = "NetBIOS NBSTAT query - name table and MAC address"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = function(host, port)
    return port.number == 137 and port.protocol == "udp"
end

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- NBSTAT query (Node Status Request)
    -- Transaction ID: 0x0001
    -- Flags: 0x0000
    -- Questions: 1
    -- Name: * (wildcard) padded to 32 bytes NBNS encoded
    local query = ""
        .. "\x00\x01" -- Transaction ID
        .. "\x00\x00" -- Flags
        .. "\x00\x01" -- Questions
        .. "\x00\x00" -- Answer RRs
        .. "\x00\x00" -- Authority RRs
        .. "\x00\x00" -- Additional RRs
        -- Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (wildcard *)
        .. "\x20"      -- Name length (32)
        .. "\x43\x4B" -- * encoded
        .. "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        .. "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        .. "\x00"      -- End of name
        .. "\x00\x21" -- Type: NBSTAT
        .. "\x00\x01" -- Class: IN

    status, err = socket:send(query)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 57 then
        return nil
    end

    -- Parse response
    -- Skip header (12 bytes) + question (skip name + type + class)
    -- Find the start of the answer section
    local offset = 13 -- past header

    -- Skip question name
    while offset <= #data do
        local len = data:byte(offset)
        if not len or len == 0 then
            offset = offset + 1
            break
        end
        offset = offset + len + 1
    end
    offset = offset + 4 -- skip type + class

    -- Answer section: skip name pointer (2) + type (2) + class (2) + TTL (4) + rdlength (2)
    offset = offset + 2 + 2 + 2 + 4 + 2

    -- Number of names
    if offset > #data then
        return nil
    end
    local num_names = data:byte(offset)
    if not num_names then
        return nil
    end
    offset = offset + 1

    local names = {}
    for i = 1, num_names do
        if offset + 17 > #data then
            break
        end
        -- Each entry: 15-byte name + 1-byte suffix + 2-byte flags
        local name = data:sub(offset, offset + 14):gsub("%s+$", "")
        local suffix = data:byte(offset + 15)
        offset = offset + 18

        if suffix then
            local suffix_desc = ""
            if suffix == 0x00 then
                suffix_desc = "<workstation>"
            elseif suffix == 0x03 then
                suffix_desc = "<messenger>"
            elseif suffix == 0x20 then
                suffix_desc = "<file server>"
            elseif suffix == 0x1D then
                suffix_desc = "<master browser>"
            elseif suffix == 0x1B then
                suffix_desc = "<domain master>"
            else
                suffix_desc = string.format("<0x%02X>", suffix)
            end
            names[#names + 1] = name .. " " .. suffix_desc
        end
    end

    -- MAC address (6 bytes after names)
    local mac = nil
    if offset + 5 <= #data then
        local mac_parts = {}
        for i = 0, 5 do
            mac_parts[#mac_parts + 1] = string.format("%02X", data:byte(offset + i))
        end
        mac = table.concat(mac_parts, ":")
    end

    local result = {}
    if #names > 0 then
        result[#result + 1] = "Names: " .. table.concat(names, ", ")
    end
    if mac then
        result[#result + 1] = "MAC: " .. mac
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
