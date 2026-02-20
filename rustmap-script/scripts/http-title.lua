summary = "Shows the title of a web page"
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

    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
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

    local title = response:match("<[Tt][Ii][Tt][Ll][Ee]>(.-)</[Tt][Ii][Tt][Ll][Ee]>")
    if title then
        title = title:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
        return "Title: " .. title
    end

    return nil
end
