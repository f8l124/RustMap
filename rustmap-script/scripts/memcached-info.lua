summary = "Queries memcached stats for version, uptime, and memory usage"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({11211}, {"memcached", "memcache"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    status, err = socket:send("stats\r\n")
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
        if response:match("END") then break end
        if #response > max_response_size then break end
    end
    socket:close()

    if #response == 0 then
        return nil
    end

    local result = {}

    local version = response:match("STAT version ([^\r\n]+)")
    if version then
        result[#result + 1] = "Version: " .. version
    end

    local uptime = response:match("STAT uptime (%d+)")
    if uptime then
        local secs = tonumber(uptime)
        if secs then
            local days = math.floor(secs / 86400)
            local hours = math.floor((secs % 86400) / 3600)
            result[#result + 1] = string.format("Uptime: %dd %dh", days, hours)
        end
    end

    local bytes_used = response:match("STAT bytes (%d+)")
    if bytes_used then
        local mb = tonumber(bytes_used) / (1024 * 1024)
        result[#result + 1] = string.format("Memory: %.1f MB", mb)
    end

    local curr_items = response:match("STAT curr_items (%d+)")
    if curr_items then
        result[#result + 1] = "Items: " .. curr_items
    end

    local curr_connections = response:match("STAT curr_connections (%d+)")
    if curr_connections then
        result[#result + 1] = "Connections: " .. curr_connections
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
