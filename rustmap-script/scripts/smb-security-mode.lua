summary = "Reports SMB signing configuration (required/enabled/disabled)"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({445}, {"microsoft-ds"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- SMB2 Negotiate with SMB 2.0.2 and 2.1
    local negotiate = ""
        .. "\x00\x00\x00\x68" -- NetBIOS length: 104 (64-byte header + 36-byte fixed + 4-byte dialects)
        .. "\xFE\x53\x4D\x42" -- SMB2 magic
        .. "\x40\x00"         -- Header length
        .. "\x00\x00"         -- Credit charge
        .. "\x00\x00\x00\x00" -- Status
        .. "\x00\x00"         -- Command: Negotiate
        .. "\x00\x00"         -- Credits
        .. "\x00\x00\x00\x00" -- Flags
        .. "\x00\x00\x00\x00" -- Next command
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Message ID
        .. "\x00\x00\x00\x00" -- Process ID
        .. "\x00\x00\x00\x00" -- Tree ID
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Session ID
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Signature
        -- Body
        .. "\x24\x00"         -- Structure size
        .. "\x02\x00"         -- Dialect count: 2
        .. "\x01\x00"         -- Security mode: signing enabled
        .. "\x00\x00"         -- Reserved
        .. "\x00\x00\x00\x00" -- Capabilities
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Client GUID
        .. "\x00\x00\x00\x00" -- Negotiate context offset
        .. "\x00\x00"         -- Negotiate context count
        .. "\x00\x00"         -- Reserved2
        .. "\x02\x02"         -- Dialect: SMB 2.0.2
        .. "\x10\x02"         -- Dialect: SMB 2.1

    status, err = socket:send(negotiate)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 72 then
        return nil
    end

    -- Verify SMB2 magic after NetBIOS header
    if data:sub(5, 8) ~= "\xFE\x53\x4D\x42" then
        return nil
    end

    -- Security mode is at offset 3 of negotiate response body
    -- SMB2 header is 64 bytes, starts at offset 5 (after 4-byte NetBIOS)
    local sec_mode_offset = 5 + 64 + 2 -- structure_size(2) + security_mode
    if #data < sec_mode_offset then
        return nil
    end

    local sec_mode = data:byte(sec_mode_offset)
    if not sec_mode then
        return nil
    end

    local signing_enabled = (sec_mode % 2) == 1
    local signing_required = (math.floor(sec_mode / 2) % 2) == 1

    if signing_required then
        return "Message signing: REQUIRED"
    elseif signing_enabled then
        return "Message signing: enabled but not required"
    else
        return "Message signing: disabled"
    end
end
