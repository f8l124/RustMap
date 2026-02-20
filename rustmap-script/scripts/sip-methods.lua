summary = "SIP OPTIONS - supported methods and Server header"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

-- Note: SIP typically uses UDP on port 5060, but this script uses TCP for simplicity
-- (stream-based I/O avoids UDP datagram fragmentation issues). This works on TCP SIP
-- endpoints, which are common on port 5060 (TCP) and 5061 (TLS).
-- portrule matches both TCP and UDP service names.
portrule = shortport.port_or_service({5060, 5061}, {"sip", "sips"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- SIP OPTIONS request
    local request = "OPTIONS sip:" .. host.ip .. " SIP/2.0\r\n"
        .. "Via: SIP/2.0/TCP " .. host.ip .. ";branch=z9hG4bK-rustmap\r\n"
        .. "Max-Forwards: 70\r\n"
        .. "To: <sip:" .. host.ip .. ">\r\n"
        .. "From: <sip:rustmap@scanner>;tag=rustmap001\r\n"
        .. "Call-ID: rustmap-scan-001@scanner\r\n"
        .. "CSeq: 1 OPTIONS\r\n"
        .. "Contact: <sip:rustmap@scanner>\r\n"
        .. "Accept: application/sdp\r\n"
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

    -- Status line
    local status_line = response:match("^SIP/2%.0 (%d+ [^\r\n]+)")
    if status_line then
        result[#result + 1] = "Status: " .. status_line
    end

    -- Allow header (supported methods)
    local allow = response:match("[Aa]llow:%s*([^\r\n]+)")
    if allow then
        result[#result + 1] = "Methods: " .. allow
    end

    -- Server header
    local server = response:match("[Ss]erver:%s*([^\r\n]+)")
    if server then
        result[#result + 1] = "Server: " .. server
    end

    -- User-Agent
    local ua = response:match("[Uu]ser%-[Aa]gent:%s*([^\r\n]+)")
    if ua then
        result[#result + 1] = "User-Agent: " .. ua
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
