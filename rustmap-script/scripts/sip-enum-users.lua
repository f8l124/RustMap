summary = "SIP REGISTER with test extension - info disclosure check"
categories = {"safe", "discovery"}
phases = {"portrule"}

-- Note: SIP typically uses UDP on port 5060, but this script uses TCP for simplicity
-- (stream-based I/O avoids UDP datagram fragmentation issues). This works on TCP SIP
-- endpoints. UDP SIP endpoints will not be reached by this script.
-- portrule matches both TCP and UDP service names.
portrule = shortport.port_or_service({5060}, {"sip"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- SIP REGISTER request for test extension "100"
    local request = "REGISTER sip:" .. host.ip .. " SIP/2.0\r\n"
        .. "Via: SIP/2.0/TCP " .. host.ip .. ";branch=z9hG4bK-rustmap-reg\r\n"
        .. "Max-Forwards: 70\r\n"
        .. "To: <sip:100@" .. host.ip .. ">\r\n"
        .. "From: <sip:100@" .. host.ip .. ">;tag=rustmap002\r\n"
        .. "Call-ID: rustmap-register-001@scanner\r\n"
        .. "CSeq: 1 REGISTER\r\n"
        .. "Contact: <sip:100@scanner>\r\n"
        .. "Content-Length: 0\r\n"
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

    local status_code = response:match("^SIP/2%.0 (%d+)")
    if not status_code then
        return nil
    end

    local code = tonumber(status_code)
    if code == 200 then
        result[#result + 1] = "Registration accepted (no auth required!)"
    elseif code == 401 then
        result[#result + 1] = "Authentication required (extension exists)"
        -- Extract WWW-Authenticate for realm info
        local realm = response:match('realm="([^"]+)"')
        if realm then
            result[#result + 1] = "Realm: " .. realm
        end
    elseif code == 403 then
        result[#result + 1] = "Registration forbidden"
    elseif code == 404 then
        result[#result + 1] = "Extension not found"
    else
        result[#result + 1] = "Response: " .. status_code
    end

    -- Server header
    local server = response:match("[Ss]erver:%s*([^\r\n]+)")
    if server then
        result[#result + 1] = "Server: " .. server
    end

    return table.concat(result, "; ")
end
