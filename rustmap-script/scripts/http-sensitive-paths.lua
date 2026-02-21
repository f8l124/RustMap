summary = "Checks for common sensitive paths and files"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"}, nil, nil)

function action(host, port)
    local paths = {
        "/.git/HEAD",
        "/.env",
        "/.DS_Store",
        "/wp-config.php.bak",
        "/.htaccess",
        "/.htpasswd",
        "/server-status",
        "/server-info",
        "/.svn/entries",
        "/web.config",
        "/crossdomain.xml",
        "/phpinfo.php",
        "/info.php",
        "/.well-known/security.txt",
        "/sitemap.xml",
    }

    local found = {}

    for _, path in ipairs(paths) do
        local socket = nmap.new_socket()
        socket:set_timeout(3000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto continue
        end

        local request = "HEAD " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
        status, err = socket:send(request)
        if not status then
            socket:close()
            goto continue
        end

        local max_response_size = 4096
        local response = ""
        while true do
            local ok, data = socket:receive()
            if not ok then break end
            response = response .. data
            if #response > max_response_size then break end
        end
        socket:close()

        local code = response:match("^HTTP/%d[%.%d]* (%d+)")
        if code == "200" then
            local size = response:match("[Cc]ontent%-[Ll]ength:%s*(%d+)")
            if size then
                found[#found + 1] = path .. " (" .. size .. " bytes)"
            else
                found[#found + 1] = path
            end
        end

        ::continue::
    end

    if #found == 0 then
        return nil
    end

    return "Sensitive paths found: " .. table.concat(found, ", ")
end
