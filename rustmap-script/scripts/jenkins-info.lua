summary = "Detects Jenkins via HTTP response headers"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({8080, 8443, 443}, {"http", "https", "jenkins"}, nil, nil)

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

    local max_response_size = 1048576
    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if #response > max_response_size then break end
    end
    socket:close()

    -- Extract headers only
    local headers = response:match("^(.-)\r\n\r\n")
    if not headers then
        return nil
    end

    local result = {}

    local jenkins_ver = headers:match("[Xx]%-[Jj]enkins:%s*([^\r\n]+)")
    if jenkins_ver then
        result[#result + 1] = "Jenkins " .. jenkins_ver
    end

    local hudson = headers:match("[Xx]%-[Hh]udson:%s*([^\r\n]+)")
    if hudson then
        result[#result + 1] = "Hudson: " .. hudson
    end

    local session = headers:match("[Xx]%-[Jj]enkins%-[Ss]ession:%s*([^\r\n]+)")
    if session then
        result[#result + 1] = "Session: " .. session:sub(1, 8)
    end

    local cli_port = headers:match("[Xx]%-[Jj]enkins%-[Cc][Ll][Ii]%-[Pp]ort:%s*(%d+)")
    if cli_port then
        result[#result + 1] = "CLI-Port: " .. cli_port
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
