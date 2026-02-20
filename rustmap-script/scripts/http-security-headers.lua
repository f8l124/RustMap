summary = "Checks for missing HTTP security headers"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
    status, err = socket:send(request)
    if not status then
        socket:close()
        return nil
    end

    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
    end
    socket:close()

    -- Extract headers (before body)
    local headers = response:match("^(.-)\r\n\r\n")
    if not headers then
        return nil
    end

    local lower_headers = headers:lower()

    local checks = {
        {"X-Frame-Options", "x%-frame%-options"},
        {"X-Content-Type-Options", "x%-content%-type%-options"},
        {"X-XSS-Protection", "x%-xss%-protection"},
        {"Content-Security-Policy", "content%-security%-policy"},
        {"Strict-Transport-Security", "strict%-transport%-security"},
        {"Referrer-Policy", "referrer%-policy"},
    }

    local present = {}
    local missing = {}

    for _, check in ipairs(checks) do
        local name, pattern = check[1], check[2]
        if lower_headers:match(pattern) then
            present[#present + 1] = name
        else
            missing[#missing + 1] = name
        end
    end

    local result = {}
    if #present > 0 then
        result[#result + 1] = "Present: " .. table.concat(present, ", ")
    end
    if #missing > 0 then
        result[#result + 1] = "Missing: " .. table.concat(missing, ", ")
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
