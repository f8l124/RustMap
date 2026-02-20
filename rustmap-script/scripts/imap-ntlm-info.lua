summary = "Extracts NTLM info from IMAP AUTHENTICATE"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({143, 993}, {"imap", "imaps"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read greeting
    local ok, data = socket:receive()
    if not ok then
        socket:close()
        return nil
    end

    local result = {}

    -- Check if NTLM is in capabilities
    status, err = socket:send("a001 CAPABILITY\r\n")
    if not status then
        socket:close()
        return nil
    end

    local response = ""
    for i = 1, 3 do
        ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if response:match("a001 ") then break end
    end

    local has_ntlm = response:upper():match("NTLM")
    if not has_ntlm then
        socket:send("a002 LOGOUT\r\n")
        socket:close()
        return nil
    end

    result[#result + 1] = "NTLM authentication supported"

    -- Send AUTHENTICATE NTLM with Type 1 (negotiate) message
    -- This is a base64-encoded NTLMSSP_NEGOTIATE message
    -- NTLMSSP\0 + Type1(0x01) + Flags(negotiate NTLM + Unicode)
    status, err = socket:send("a002 AUTHENTICATE NTLM\r\n")
    if not status then
        socket:close()
        return table.concat(result, "; ")
    end

    -- Read continuation
    ok, data = socket:receive()
    if not ok then
        socket:close()
        return table.concat(result, "; ")
    end

    if data:match("^%+") then
        -- Send NTLM Type 1 negotiate message (base64 encoded)
        -- Minimal NTLM negotiate: NTLMSSP\0\x01\x00\x00\x00\x07\x82\x08\xa2
        local ntlm_negotiate = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
        socket:send(ntlm_negotiate .. "\r\n")

        -- Read Type 2 challenge
        ok, data = socket:receive()
        if ok and data and data:match("^%+") then
            -- Got Type 2 challenge - server supports NTLM
            result[#result + 1] = "NTLM challenge received"
        end
    end

    -- Cancel auth
    socket:send("*\r\n")
    socket:send("a003 LOGOUT\r\n")
    socket:close()

    return table.concat(result, "; ")
end
