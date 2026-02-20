summary = "Checks if anonymous FTP login is allowed"
categories = {"default", "safe", "auth"}
phases = {"portrule"}

portrule = shortport.port_or_service({21}, {"ftp"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read the greeting banner
    local ok, greeting = socket:receive()
    if not ok then
        socket:close()
        return nil
    end

    -- Send anonymous login
    status, err = socket:send("USER anonymous\r\n")
    if not status then
        socket:close()
        return nil
    end

    ok, data = socket:receive()
    if not ok then
        socket:close()
        return nil
    end

    -- 331 means server wants a password, 230 means logged in immediately
    local code = tonumber(data:match("^(%d+)"))
    if code == 230 then
        socket:send("QUIT\r\n")
        socket:close()
        return "Anonymous login allowed (no password required)"
    end

    if code ~= 331 then
        socket:send("QUIT\r\n")
        socket:close()
        return nil
    end

    -- Send password (convention: email-style)
    status, err = socket:send("PASS guest@\r\n")
    if not status then
        socket:close()
        return nil
    end

    ok, data = socket:receive()
    if not ok then
        socket:send("QUIT\r\n")
        socket:close()
        return nil
    end

    code = tonumber(data:match("^(%d+)"))
    socket:send("QUIT\r\n")
    socket:close()

    if code == 230 then
        return "Anonymous login allowed (password accepted)"
    elseif code == 530 then
        return "Anonymous login denied"
    end

    return nil
end
