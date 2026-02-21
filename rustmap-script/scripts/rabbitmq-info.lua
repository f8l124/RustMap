summary = "Queries RabbitMQ management API for cluster info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({15672}, {"rabbitmq-management"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Try default guest:guest credentials (base64 "guest:guest" = "Z3Vlc3Q6Z3Vlc3Q=")
    local request = "GET /api/overview HTTP/1.1\r\n" ..
        "Host: " .. host.ip .. "\r\n" ..
        "Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n" ..
        "Connection: close\r\n\r\n"
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

    local status_code = response:match("^HTTP/%d[%.%d]* (%d+)")
    if not status_code then
        return nil
    end

    if status_code == "401" then
        return "RabbitMQ Management: authentication required (default credentials rejected)"
    end

    if status_code ~= "200" then
        return nil
    end

    local body = response:match("\r\n\r\n(.+)")
    if not body then
        return nil
    end

    local result = {}

    local version = body:match('"rabbitmq_version"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "RabbitMQ " .. version
    end

    local erlang = body:match('"erlang_version"%s*:%s*"([^"]+)"')
    if erlang then
        result[#result + 1] = "Erlang: " .. erlang
    end

    local cluster_name = body:match('"cluster_name"%s*:%s*"([^"]+)"')
    if cluster_name then
        result[#result + 1] = "Cluster: " .. cluster_name
    end

    local node = body:match('"node"%s*:%s*"([^"]+)"')
    if node then
        result[#result + 1] = "Node: " .. node
    end

    if version then
        result[#result + 1] = "WARNING: default credentials (guest:guest) accepted"
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
