summary = "Extracts SMB2 negotiate info: signing mode, dialect, and server GUID"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({445, 139}, {"microsoft-ds", "netbios-ssn"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- SMB2 Negotiate Request
    -- NetBIOS session header + SMB2 header + Negotiate request
    -- Offer all 5 SMB2/3 dialects so the server selects its highest supported version
    local smb2_negotiate = ""
        .. "\x00\x00\x00\x6E" -- NetBIOS: length 110 (64-byte header + 36-byte fixed + 10-byte dialects)
        .. "\xFE\x53\x4D\x42" -- SMB2 magic
        .. "\x40\x00"         -- Header length 64
        .. "\x00\x00"         -- Credit charge
        .. "\x00\x00\x00\x00" -- Status
        .. "\x00\x00"         -- Command: Negotiate
        .. "\x00\x00"         -- Credits requested
        .. "\x00\x00\x00\x00" -- Flags
        .. "\x00\x00\x00\x00" -- Next command
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Message ID
        .. "\x00\x00\x00\x00" -- Process ID
        .. "\x00\x00\x00\x00" -- Tree ID
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Session ID
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Signature
        -- Negotiate body
        .. "\x24\x00"         -- Structure size 36
        .. "\x05\x00"         -- Dialect count: 5
        .. "\x01\x00"         -- Security mode: signing enabled
        .. "\x00\x00"         -- Reserved
        .. "\x00\x00\x00\x00" -- Capabilities
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Client GUID
        .. "\x00\x00\x00\x00" -- Negotiate context offset
        .. "\x00\x00"         -- Negotiate context count
        .. "\x00\x00"         -- Reserved2
        .. "\x02\x02"         -- Dialect: SMB 2.0.2
        .. "\x10\x02"         -- Dialect: SMB 2.1
        .. "\x00\x03"         -- Dialect: SMB 3.0
        .. "\x02\x03"         -- Dialect: SMB 3.0.2
        .. "\x11\x03"         -- Dialect: SMB 3.1.1

    status, err = socket:send(smb2_negotiate)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 72 then
        return nil
    end

    -- Check for SMB2 magic
    -- Skip 4-byte NetBIOS header
    local offset = 5
    if data:sub(offset, offset + 3) ~= "\xFE\x53\x4D\x42" then
        return nil
    end

    local result = {}

    -- Extract signing mode from negotiate response
    -- Security mode is at byte offset 2 of the negotiate response body (after 64-byte SMB2 header)
    -- Values: 1 = signing enabled, 3 = signing required
    local sec_offset = offset + 64 + 2
    if #data >= sec_offset then
        local sec_mode = data:byte(sec_offset)
        if sec_mode then
            if sec_mode == 1 then
                result[#result + 1] = "Signing: enabled"
            elseif sec_mode == 3 then
                result[#result + 1] = "Signing: required"
            end
        end
    end

    -- Dialect selected (offset 4-5 of negotiate body, little-endian 16-bit)
    local dialect_offset = offset + 64 + 4
    if #data >= dialect_offset + 1 then
        local d1 = data:byte(dialect_offset)
        local d2 = data:byte(dialect_offset + 1)
        if d1 and d2 then
            local dialect = d1 + d2 * 256
            if dialect == 0x0202 then
                result[#result + 1] = "Dialect: SMB 2.0.2"
            elseif dialect == 0x0210 then
                result[#result + 1] = "Dialect: SMB 2.1"
            elseif dialect == 0x0300 then
                result[#result + 1] = "Dialect: SMB 3.0"
            elseif dialect == 0x0302 then
                result[#result + 1] = "Dialect: SMB 3.0.2"
            elseif dialect == 0x0311 then
                result[#result + 1] = "Dialect: SMB 3.1.1"
            else
                result[#result + 1] = string.format("Dialect: 0x%04X", dialect)
            end
        end
    end

    -- Server GUID (offset 8 of negotiate body, 16 bytes)
    local guid_offset = offset + 64 + 8
    if #data >= guid_offset + 15 then
        local guid_parts = {}
        for i = 0, 15 do
            guid_parts[#guid_parts + 1] = string.format("%02x", data:byte(guid_offset + i))
        end
        result[#result + 1] = "GUID: " .. table.concat(guid_parts)
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
