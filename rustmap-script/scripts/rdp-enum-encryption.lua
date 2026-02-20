summary = "Enumerates RDP encryption levels"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({3389}, {"ms-wbt-server", "rdp"}, nil, nil)

function action(host, port)
    local protocols = {
        {"\x00\x00\x00\x00", "Standard RDP Security"},
        {"\x01\x00\x00\x00", "TLS"},
        {"\x02\x00\x00\x00", "CredSSP (NLA)"},
        {"\x03\x00\x00\x00", "CredSSP + TLS"},
    }

    local supported = {}

    for _, entry in ipairs(protocols) do
        local proto_bytes, proto_name = entry[1], entry[2]

        local socket = nmap.new_socket()
        socket:set_timeout(3000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto next_proto
        end

        local rdp_neg = ""
            .. "\x03\x00"     -- TPKT version 3
            .. "\x00\x13"     -- TPKT length: 19
            .. "\x0E"         -- X.224 length
            .. "\xE0"         -- Connection Request
            .. "\x00\x00"     -- DST-REF
            .. "\x00\x00"     -- SRC-REF
            .. "\x00"         -- Class 0
            .. "\x01"         -- Negotiation Request
            .. "\x00"         -- Flags
            .. "\x08\x00"     -- Length: 8
            .. proto_bytes     -- Requested protocol

        status, err = socket:send(rdp_neg)
        if not status then
            socket:close()
            goto next_proto
        end

        local ok, data = socket:receive()
        socket:close()

        if ok and data and #data >= 11 then
            -- Connection Confirm
            if data:byte(6) == 0xD0 then
                -- For Standard RDP (0x00), a Connection Confirm without
                -- negotiation response means it's supported
                if proto_bytes == "\x00\x00\x00\x00" then
                    -- Standard RDP: confirm if no negotiation response or
                    -- if negotiation response type is 0x02
                    if #data < 16 or data:byte(12) == 0x02 then
                        supported[#supported + 1] = proto_name
                    end
                elseif #data >= 19 and data:byte(12) == 0x02 then
                    -- Verify the selected protocol in bytes 16-19 matches request
                    local selected = data:byte(16)
                    local requested = proto_bytes:byte(1)
                    if selected and selected == requested then
                        supported[#supported + 1] = proto_name
                    end
                end
            end
        end

        ::next_proto::
    end

    if #supported == 0 then
        return nil
    end

    return "Supported: " .. table.concat(supported, ", ")
end
