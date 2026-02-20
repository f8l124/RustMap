summary = "Reports supported SMTP commands via EHLO"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({25, 465, 587}, {"smtp", "smtps", "submission"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read the greeting banner
    local ok, greeting = socket:receive()
    if not ok then
        socket:close()
        return nil
    end

    -- Send EHLO
    status, err = socket:send("EHLO rustmap\r\n")
    if not status then
        socket:close()
        return nil
    end

    -- Read EHLO response (may be multi-line)
    local response = ""
    while true do
        ok, data = socket:receive()
        if not ok then break end
        response = response .. data
    end

    -- Send QUIT
    socket:send("QUIT\r\n")
    socket:close()

    if #response == 0 then
        return nil
    end

    -- Parse EHLO extensions from multi-line response
    -- Lines look like: "250-PIPELINING" or "250 SIZE 10240000"
    local extensions = {}
    for line in response:gmatch("[^\r\n]+") do
        local ext = line:match("^250[%- ](.+)")
        if ext then
            extensions[#extensions + 1] = ext
        end
    end

    if #extensions > 0 then
        -- Extract banner info
        local banner = greeting:gsub("[\r\n]+$", ""):match("^220%s*(.*)")

        local result = ""
        if banner then
            result = banner .. "\n"
        end
        result = result .. "Commands: " .. table.concat(extensions, ", ")
        return result
    end

    return nil
end
