summary = "IMAP greeting and CAPABILITY command"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({143, 993}, {"imap", "imaps"}, nil, nil)

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

    -- Parse greeting
    greeting = greeting:gsub("[\r\n]+$", "")
    if greeting:match("^%* OK") then
        local banner = greeting:match("^%* OK%s*(.*)")
        if banner and #banner > 0 then
            result[#result + 1] = "Banner: " .. banner
        end
    elseif greeting:match("^%* PREAUTH") then
        result[#result + 1] = "Pre-authenticated connection"
    end

    -- Send CAPABILITY command
    status, err = socket:send("a001 CAPABILITY\r\n")
    if not status then
        socket:close()
        return table.concat(result, "; ")
    end

    local response = ""
    for _ = 1, 3 do
        local recv_ok, data = socket:receive()
        if not recv_ok then break end
        response = response .. data
        if response:match("a001 ") then break end
    end

    -- Extract capabilities
    local caps = response:match("%* CAPABILITY ([^\r\n]+)")
    if caps then
        result[#result + 1] = "Capabilities: " .. caps
    end

    -- Logout
    socket:send("a002 LOGOUT\r\n")
    socket:close()

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
