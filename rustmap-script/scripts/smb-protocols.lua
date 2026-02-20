summary = "Enumerates supported SMB protocol versions via negotiate"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({445}, {"microsoft-ds"}, nil, nil)

function action(host, port)
    -- Test each SMB dialect individually
    local dialects = {
        {"\x02\x02", "SMB 2.0.2"},
        {"\x10\x02", "SMB 2.1"},
        {"\x00\x03", "SMB 3.0"},
        {"\x02\x03", "SMB 3.0.2"},
        {"\x11\x03", "SMB 3.1.1"},
    }

    local supported = {}

    for _, entry in ipairs(dialects) do
        local dialect_bytes, dialect_name = entry[1], entry[2]

        local socket = nmap.new_socket()
        socket:set_timeout(3000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto next_dialect
        end

        -- SMB2 negotiate with single dialect
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
            -- Negotiate body
            .. "\x24\x00"         -- Structure size
            .. "\x01\x00"         -- Dialect count: 1
            .. "\x01\x00"         -- Security mode
            .. "\x00\x00"         -- Reserved
            .. "\x00\x00\x00\x00" -- Capabilities
            .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- Client GUID
            .. "\x00\x00\x00\x00" -- Negotiate context offset
            .. "\x00\x00"         -- Negotiate context count
            .. "\x00\x00"         -- Reserved2
            .. dialect_bytes      -- Single dialect

        status, err = socket:send(negotiate)
        if not status then
            socket:close()
            goto next_dialect
        end

        local ok, data = socket:receive()
        socket:close()

        if ok and data and #data >= 72 then
            -- Check SMB2 magic at offset 5 (after NetBIOS header)
            if data:sub(5, 8) == "\xFE\x53\x4D\x42" then
                -- Check NT_STATUS is SUCCESS (0x00000000) at offset 12-15
                local s1 = data:byte(13)
                local s2 = data:byte(14)
                local s3 = data:byte(15)
                local s4 = data:byte(16)
                if s1 == 0 and s2 == 0 and s3 == 0 and s4 == 0 then
                    supported[#supported + 1] = dialect_name
                end
            end
        end

        ::next_dialect::
    end

    if #supported == 0 then
        return nil
    end

    return "Supported: " .. table.concat(supported, ", ")
end
