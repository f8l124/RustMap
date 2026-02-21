summary = "Lists available rsync modules"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({873}, {"rsync"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read server greeting
    local ok, greeting = socket:receive()
    if not ok then
        socket:close()
        return nil
    end

    -- Check for rsync protocol
    if not greeting:match("^@RSYNCD:") then
        socket:close()
        return nil
    end

    -- Send our version and request module listing
    status, err = socket:send("@RSYNCD: 31.0\n#list\n")
    if not status then
        socket:close()
        return nil
    end

    local max_response_size = 65536
    local response = ""
    while true do
        ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if #response > max_response_size then break end
        if response:match("@RSYNCD: EXIT") then break end
    end
    socket:close()

    local modules = {}
    for line in response:gmatch("[^\n]+") do
        if not line:match("^@RSYNCD:") then
            local name, desc = line:match("^(%S+)%s+(.*)")
            if name then
                modules[#modules + 1] = name .. " - " .. desc
            elseif line:match("^%S+$") then
                modules[#modules + 1] = line
            end
        end
    end

    if #modules == 0 then
        return "rsync " .. greeting:match("@RSYNCD:%s*(.+)") .. " (no modules listed)"
    end

    local version = greeting:match("@RSYNCD:%s*(.+)") or "unknown"
    return "rsync " .. version .. "; Modules: " .. table.concat(modules, ", ")
end
