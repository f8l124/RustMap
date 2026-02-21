summary = "Queries HashiCorp Consul agent info via REST API"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({8500}, {"consul"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET /v1/agent/self HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
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

    local result = {}

    local datacenter = body:match('"Datacenter"%s*:%s*"([^"]+)"')
    if datacenter then
        result[#result + 1] = "DC: " .. datacenter
    end

    local node_name = body:match('"NodeName"%s*:%s*"([^"]+)"')
    if node_name then
        result[#result + 1] = "Node: " .. node_name
    end

    local revision = body:match('"Revision"%s*:%s*"([^"]+)"')
    if revision then
        result[#result + 1] = "Revision: " .. revision
    end

    local version = body:match('"Version"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "Version: " .. version
    end

    local server = body:match('"Server"%s*:%s*(true)')
    if server then
        result[#result + 1] = "Role: server"
    else
        result[#result + 1] = "Role: client"
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
