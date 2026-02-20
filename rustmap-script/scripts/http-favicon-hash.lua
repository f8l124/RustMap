summary = "Downloads /favicon.ico and computes MD5 hash (Shodan-style fingerprint)"
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

    local request = "GET /favicon.ico HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
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

    -- Check for 200 OK
    if not response:match("^HTTP/%d[%.%d]* 200") then
        return nil
    end

    -- Extract body after headers
    local body = response:match("\r\n\r\n(.+)")
    if not body or #body == 0 then
        return nil
    end

    local hash = nmap.md5(body)
    return "favicon MD5: " .. hash
end
