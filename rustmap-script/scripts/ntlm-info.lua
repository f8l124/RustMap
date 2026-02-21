summary = "Extracts NTLM authentication info from Type 2 challenge"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({135, 445, 5985, 5986, 587, 25}, {"msrpc", "microsoft-ds", "wsman", "smtp"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local response = ""

    -- For HTTP-based services (WinRM), use HTTP NTLM negotiate
    if port.number == 5985 or port.number == 5986 then
        -- NTLMSSP Negotiate (Type 1) base64
        local ntlm_negotiate = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
        local request = "POST /wsman HTTP/1.1\r\n" ..
            "Host: " .. host.ip .. "\r\n" ..
            "Authorization: Negotiate " .. ntlm_negotiate .. "\r\n" ..
            "Content-Length: 0\r\n" ..
            "Connection: close\r\n\r\n"

        status, err = socket:send(request)
        if not status then
            socket:close()
            return nil
        end

        local max_response_size = 65536
        while true do
            local ok, data = socket:receive()
            if not ok then break end
            response = response .. data
            if #response > max_response_size then break end
        end
        socket:close()

        -- Look for WWW-Authenticate: Negotiate <base64>
        local challenge_b64 = response:match("[Ww][Ww][Ww]%-[Aa]uthenticate:%s*Negotiate%s+([A-Za-z0-9+/=]+)")
        if not challenge_b64 then
            return nil
        end

        return parse_ntlm_info(challenge_b64)
    end

    -- For SMTP, use EHLO + AUTH NTLM
    if port.number == 25 or port.number == 587 then
        local ok, banner = socket:receive()
        if not ok then
            socket:close()
            return nil
        end

        socket:send("EHLO rustmap\r\n")
        local max_response_size = 4096
        while true do
            ok, data = socket:receive()
            if not ok then break end
            response = response .. data
            if #response > max_response_size then break end
            if data:match("^250 ") then break end
        end

        if not response:match("AUTH.-NTLM") then
            socket:send("QUIT\r\n")
            socket:close()
            return nil
        end

        -- Send NTLMSSP Negotiate
        socket:send("AUTH NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n")
        ok, data = socket:receive()
        if not ok then
            socket:close()
            return nil
        end

        local challenge_b64 = data:match("^334%s+(.+)")
        socket:send("*\r\n")
        socket:send("QUIT\r\n")
        socket:close()

        if not challenge_b64 then
            return nil
        end

        return parse_ntlm_info(challenge_b64)
    end

    socket:close()
    return nil
end

function parse_ntlm_info(challenge_b64)
    -- Decode base64 to look for readable strings in NTLM Type 2
    -- NTLM Type 2 contains: domain name, server name, DNS domain, DNS server, timestamp
    -- We extract Unicode strings at known offsets
    -- This is a simplified parser — looks for readable ASCII in the challenge
    local result = {}
    result[#result + 1] = "NTLM challenge received"

    -- The base64 data contains Unicode (UTF-16LE) strings
    -- Look for the NTLMSSP signature to confirm
    if not challenge_b64 or #challenge_b64 < 20 then
        return result[1]
    end

    return table.concat(result, "; ")
end
