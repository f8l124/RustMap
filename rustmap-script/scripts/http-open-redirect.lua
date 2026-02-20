summary = "Tests for open redirect in common query parameters (GET only)"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"}, nil, nil)

function action(host, port)
    local params = {"url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "dest"}
    local test_domain = "http://example.com"

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local vulnerable = {}

    for _, param in ipairs(params) do
        socket:close()
        local status, err = socket:connect(host.ip, port.number)
        if not status then
            return nil
        end

        local path = "/?" .. param .. "=" .. test_domain
        local request = "GET " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"

        status, err = socket:send(request)
        if not status then
            goto continue_loop
        end

        local response = ""
        while true do
            local ok, data = socket:receive()
            if not ok then break end
            response = response .. data
        end

        -- Check for redirect to our test domain
        local status_code = response:match("^HTTP/%d[%.%d]* (%d+)")
        if status_code then
            local code = tonumber(status_code)
            if code and code >= 300 and code < 400 then
                local location = response:match("[Ll]ocation:%s*([^\r\n]+)")
                if location and location:match("example%.com") then
                    vulnerable[#vulnerable + 1] = param
                end
            end
        end

        ::continue_loop::
    end

    socket:close()

    if #vulnerable == 0 then
        return nil
    end

    return "Possible open redirect via: " .. table.concat(vulnerable, ", ")
end
