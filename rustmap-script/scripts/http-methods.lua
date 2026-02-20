summary = "Discovers supported HTTP methods via OPTIONS request"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "OPTIONS / HTTP/1.1\r\nHost: " .. host.ip .. "\r\n\r\n"
    status, err = socket:send(request)
    if not status then
        socket:close()
        return nil
    end

    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
    end
    socket:close()

    if #response == 0 then
        return nil
    end

    -- Extract Allow header
    local allow = response:match("[Aa][Ll][Ll][Oo][Ww]:%s*([^\r\n]+)")
    if allow then
        return "Allowed methods: " .. allow
    end

    -- Fall back to status line
    local status_line = response:match("^(HTTP/[^\r\n]+)")
    if status_line then
        return "OPTIONS response: " .. status_line
    end

    return nil
end
