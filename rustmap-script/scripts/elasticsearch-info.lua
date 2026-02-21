summary = "Queries Elasticsearch cluster info via REST API"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({9200, 9201}, {"elasticsearch"}, nil, nil)

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

    if not response:match("^HTTP/%d[%.%d]* 200") then
        return nil
    end

    local body = response:match("\r\n\r\n(.+)")
    if not body then
        return nil
    end

    local result = {}

    local cluster_name = body:match('"cluster_name"%s*:%s*"([^"]+)"')
    if cluster_name then
        result[#result + 1] = "Cluster: " .. cluster_name
    end

    local name = body:match('"name"%s*:%s*"([^"]+)"')
    if name then
        result[#result + 1] = "Node: " .. name
    end

    local version = body:match('"number"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "Version: " .. version
    end

    local lucene = body:match('"lucene_version"%s*:%s*"([^"]+)"')
    if lucene then
        result[#result + 1] = "Lucene: " .. lucene
    end

    local build_type = body:match('"build_type"%s*:%s*"([^"]+)"')
    if build_type then
        result[#result + 1] = "Build: " .. build_type
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
