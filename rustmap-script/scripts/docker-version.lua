summary = "Queries Docker /version API endpoint"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({2375, 2376}, {"docker"}, nil, nil)

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

    local max_response_size = 1048576 -- 1 MB limit to prevent unbounded accumulation
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

    local version = body:match('"Version"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "Docker " .. version
    end

    local api_version = body:match('"ApiVersion"%s*:%s*"([^"]+)"')
    if api_version then
        result[#result + 1] = "API: " .. api_version
    end

    local os_info = body:match('"Os"%s*:%s*"([^"]+)"')
    local arch = body:match('"Arch"%s*:%s*"([^"]+)"')
    if os_info then
        local platform = os_info
        if arch then platform = platform .. "/" .. arch end
        result[#result + 1] = "Platform: " .. platform
    end

    local go_version = body:match('"GoVersion"%s*:%s*"([^"]+)"')
    if go_version then
        result[#result + 1] = "Go: " .. go_version
    end

    local kernel = body:match('"KernelVersion"%s*:%s*"([^"]+)"')
    if kernel then
        result[#result + 1] = "Kernel: " .. kernel
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
