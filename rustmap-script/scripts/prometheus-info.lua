summary = "Queries Prometheus build info via REST API"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({9090}, {"prometheus"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET /api/v1/status/buildinfo HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
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

    local version = body:match('"version"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "Prometheus " .. version
    end

    local revision = body:match('"revision"%s*:%s*"([^"]+)"')
    if revision then
        result[#result + 1] = "Rev: " .. revision:sub(1, 8)
    end

    local branch = body:match('"branch"%s*:%s*"([^"]+)"')
    if branch then
        result[#result + 1] = "Branch: " .. branch
    end

    local go_version = body:match('"goVersion"%s*:%s*"([^"]+)"')
    if go_version then
        result[#result + 1] = "Go: " .. go_version
    end

    local build_date = body:match('"buildDate"%s*:%s*"([^"]+)"')
    if build_date then
        result[#result + 1] = "Built: " .. build_date
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
