summary = "RTSP OPTIONS - supported methods"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({554, 8554}, {"rtsp"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local request = "OPTIONS rtsp://" .. host.ip .. ":" .. port.number .. " RTSP/1.0\r\n"
        .. "CSeq: 1\r\n"
        .. "User-Agent: rustmap\r\n"
        .. "\r\n"

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
        if response:match("\r\n\r\n") then break end
    end
    socket:close()

    if #response == 0 then
        return nil
    end

    local result = {}

    -- Status line
    local status_line = response:match("^RTSP/1%.0 (%d+ [^\r\n]+)")
    if status_line then
        result[#result + 1] = "RTSP " .. status_line
    end

    -- Public header (supported methods)
    local public = response:match("[Pp]ublic:%s*([^\r\n]+)")
    if public then
        result[#result + 1] = "Methods: " .. public
    end

    -- Server header
    local server = response:match("[Ss]erver:%s*([^\r\n]+)")
    if server then
        result[#result + 1] = "Server: " .. server
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
