summary = "Detects HTTP directory listing / index pages"
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

    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
    status, err = socket:send(request)
    if not status then
        socket:close()
        return nil
    end

    local max_response_size = 1048576
    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if #response > max_response_size then break end
    end
    socket:close()

    if not response:match("^HTTP/%d[%.%d]* 200") then
        return nil
    end

    local body = response:match("\r\n\r\n(.+)")
    if not body then
        return nil
    end

    local lower_body = body:lower()

    -- Apache directory listing
    if lower_body:match("<title>index of /") then
        local server = response:match("[Ss]erver:%s*([^\r\n]+)")
        local count = 0
        for _ in body:gmatch('<a href="[^"]+"') do
            count = count + 1
        end
        local msg = "Directory listing enabled (Apache-style)"
        if server then msg = msg .. "; Server: " .. server end
        if count > 0 then msg = msg .. "; " .. count .. " entries" end
        return msg
    end

    -- Nginx autoindex
    if lower_body:match("<title>index of /") or lower_body:match("nginx") and lower_body:match('<a href="[^"]+/">') then
        local count = 0
        for _ in body:gmatch('<a href="[^"]+"') do
            count = count + 1
        end
        local msg = "Directory listing enabled (nginx autoindex)"
        if count > 0 then msg = msg .. "; " .. count .. " entries" end
        return msg
    end

    -- IIS directory browsing
    if lower_body:match("%[to parent directory%]") then
        return "Directory listing enabled (IIS-style)"
    end

    -- Lighttpd
    if lower_body:match("lighttpd") and lower_body:match('<a href="[^"]+/"') then
        return "Directory listing enabled (lighttpd)"
    end

    return nil
end
