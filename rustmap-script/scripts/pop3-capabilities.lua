summary = "POP3 greeting and CAPA command"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({110, 995}, {"pop3", "pop3s"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read greeting
    local ok, greeting = socket:receive()
    if not ok or not greeting then
        socket:close()
        return nil
    end

    local result = {}

    greeting = greeting:gsub("[\r\n]+$", "")
    if greeting:match("^%+OK") then
        local banner = greeting:match("^%+OK%s*(.*)")
        if banner and #banner > 0 then
            result[#result + 1] = "Banner: " .. banner
        end
    end

    -- Send CAPA command
    status, err = socket:send("CAPA\r\n")
    if not status then
        socket:close()
        return table.concat(result, "; ")
    end

    local response = ""
    for _ = 1, 5 do
        local recv_ok, data = socket:receive()
        if not recv_ok then break end
        response = response .. data
        if response:match("%.[\r\n]") then break end
    end

    if response:match("^%+OK") then
        local caps = {}
        for cap in response:gmatch("[\r\n]([%w%-]+)") do
            if cap ~= "." then
                caps[#caps + 1] = cap
            end
        end
        if #caps > 0 then
            result[#result + 1] = "Capabilities: " .. table.concat(caps, ", ")
        end
    end

    -- Quit
    socket:send("QUIT\r\n")
    socket:close()

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
