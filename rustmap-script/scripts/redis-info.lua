summary = "Queries Redis INFO command for version, OS, and client info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({6379}, {"redis"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Send Redis INFO command (RESP protocol)
    status, err = socket:send("*1\r\n$4\r\nINFO\r\n")
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

    if #response == 0 then
        return nil
    end

    -- Check for auth required
    if response:match("NOAUTH") or response:match("%-ERR") then
        return "Redis: authentication required"
    end

    local result = {}

    local version = response:match("redis_version:([^\r\n]+)")
    if version then
        result[#result + 1] = "Version: " .. version
    end

    local mode = response:match("redis_mode:([^\r\n]+)")
    if mode then
        result[#result + 1] = "Mode: " .. mode
    end

    local os_info = response:match("os:([^\r\n]+)")
    if os_info then
        result[#result + 1] = "OS: " .. os_info
    end

    local clients = response:match("connected_clients:(%d+)")
    if clients then
        result[#result + 1] = "Clients: " .. clients
    end

    local memory = response:match("used_memory_human:([^\r\n]+)")
    if memory then
        result[#result + 1] = "Memory: " .. memory
    end

    local role = response:match("role:([^\r\n]+)")
    if role then
        result[#result + 1] = "Role: " .. role
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
