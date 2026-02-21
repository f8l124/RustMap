summary = "Queries etcd version info via REST API"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({2379, 2380}, {"etcd"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET /version HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
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

    local etcd_version = body:match('"etcdserver"%s*:%s*"([^"]+)"')
    if etcd_version then
        result[#result + 1] = "etcd: " .. etcd_version
    end

    local cluster_version = body:match('"etcdcluster"%s*:%s*"([^"]+)"')
    if cluster_version then
        result[#result + 1] = "Cluster: " .. cluster_version
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
