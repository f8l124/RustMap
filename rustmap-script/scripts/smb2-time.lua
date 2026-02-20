summary = "Extracts server time from SMB2 negotiate response"
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

    -- SMB2 Negotiate with SMB 2.0.2
    local negotiate = ""
        .. "\x00\x00\x00\x66" -- NetBIOS length (102 = 64-byte header + 38-byte body)
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
        .. "\x01\x00"         -- Dialect count: 1
        .. "\x01\x00"         -- Security mode
        .. "\x00\x00"         -- Reserved
        .. "\x00\x00\x00\x00" -- Capabilities
        .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Client GUID
        .. "\x00\x00\x00\x00" -- Negotiate context offset
        .. "\x00\x00"         -- Negotiate context count
        .. "\x00\x00"         -- Reserved2
        .. "\x02\x02"         -- Dialect: SMB 2.0.2

    status, err = socket:send(negotiate)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 120 then
        return nil
    end

    -- Verify SMB2 magic
    if data:sub(5, 8) ~= "\xFE\x53\x4D\x42" then
        return nil
    end

    -- SystemTime is at offset 40 (from negotiate body start)
    -- SMB2 header starts at offset 5 (after NetBIOS), body at offset 5+64=69
    -- SystemTime at body offset 40 = data offset 109
    local time_offset = 5 + 64 + 40
    if #data < time_offset + 7 then
        return nil
    end

    -- Read 8-byte FILETIME (100-nanosecond intervals since 1601-01-01)
    -- Note: FILETIME is a 64-bit value (~57 significant bits for current dates),
    -- but Lua numbers are IEEE 754 doubles with 53-bit mantissa. This causes up to
    -- ~1.6 seconds of precision loss, which is acceptable for display purposes.
    local filetime = 0
    for i = 7, 0, -1 do
        filetime = filetime * 256 + data:byte(time_offset + i)
    end

    if filetime == 0 then
        return nil
    end

    -- Convert FILETIME to Unix epoch
    -- FILETIME epoch is 1601-01-01, Unix is 1970-01-01
    -- Difference: 11644473600 seconds = 116444736000000000 in 100ns units
    local unix_seconds = (filetime - 116444736000000000) / 10000000

    -- Format as approximate date
    local date_str = os.date("!%Y-%m-%d %H:%M:%S UTC", math.floor(unix_seconds))
    return "Server time: " .. date_str
end
