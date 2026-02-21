summary = "Queries CouchDB server info via REST API"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({5984, 6984}, {"couchdb"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
    status, err = socket:send(request)
    if not status then
        socket:close()
        return nil
    end

    local max_response_size = 1048576
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

    local result = {}

    local couchdb = body:match('"couchdb"%s*:%s*"([^"]+)"')
    if couchdb then
        result[#result + 1] = couchdb
    end

    local version = body:match('"version"%s*:%s*"([^"]+)"')
    if version then
        result[#result + 1] = "Version: " .. version
    end

    local vendor_name = body:match('"name"%s*:%s*"([^"]+)"')
    if vendor_name and vendor_name ~= "CouchDB" then
        result[#result + 1] = "Vendor: " .. vendor_name
    end

    local uuid = body:match('"uuid"%s*:%s*"([^"]+)"')
    if uuid then
        result[#result + 1] = "UUID: " .. uuid:sub(1, 8) .. "..."
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
