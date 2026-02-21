summary = "Detects Windows Remote Management (WinRM) service"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({5985, 5986}, {"wsman", "winrm"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Send WS-Man Identify request
    local wsman_identify = '<?xml version="1.0" encoding="UTF-8"?>\r\n' ..
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' ..
        'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">' ..
        '<s:Header/><s:Body>' ..
        '<wsmid:Identify/>' ..
        '</s:Body></s:Envelope>'

    local request = "POST /wsman-anon/identify HTTP/1.1\r\n" ..
        "Host: " .. host.ip .. "\r\n" ..
        "Content-Type: application/soap+xml;charset=UTF-8\r\n" ..
        "Content-Length: " .. #wsman_identify .. "\r\n" ..
        "Connection: close\r\n\r\n" ..
        wsman_identify

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
        -- Even a non-200 on these ports suggests WinRM
        if response:match("^HTTP/%d[%.%d]* 401") then
            return "WinRM: authentication required (HTTP 401)"
        end
        return nil
    end

    local body = response:match("\r\n\r\n(.+)")
    if not body then
        return nil
    end

    local result = {}
    result[#result + 1] = "WinRM detected"

    local product_version = body:match("<wsmid:ProductVersion>([^<]+)</wsmid:ProductVersion>")
    if product_version then
        result[#result + 1] = "Version: " .. product_version
    end

    local protocol_version = body:match("<wsmid:ProtocolVersion>([^<]+)</wsmid:ProtocolVersion>")
    if protocol_version then
        result[#result + 1] = "Protocol: " .. protocol_version
    end

    local product_vendor = body:match("<wsmid:ProductVendor>([^<]+)</wsmid:ProductVendor>")
    if product_vendor then
        result[#result + 1] = "Vendor: " .. product_vendor
    end

    return table.concat(result, "; ")
end
