summary = "Queries Docker /containers/json for running container info"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({2375, 2376}, {"docker"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET /containers/json HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
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

    -- Count containers from JSON array
    local count = 0
    local names = {}

    -- Simple JSON parsing for container names
    for name in body:gmatch('"Names"%s*:%s*%[%s*"(/[^"]+)"') do
        count = count + 1
        names[#names + 1] = name:sub(2) -- remove leading /
    end

    -- If no Names found, try counting by Id fields
    if count == 0 then
        for _ in body:gmatch('"Id"%s*:') do
            count = count + 1
        end
    end

    if count == 0 then
        if body == "[]" then
            return "Docker API accessible; no running containers"
        end
        return nil
    end

    local result = string.format("Running containers: %d", count)
    if #names > 0 then
        -- Show first 5 names
        local show = {}
        for i = 1, math.min(5, #names) do
            show[#show + 1] = names[i]
        end
        result = result .. " (" .. table.concat(show, ", ")
        if #names > 5 then
            result = result .. ", ..."
        end
        result = result .. ")"
    end

    return result
end
