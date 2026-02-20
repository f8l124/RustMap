summary = "Checks CORS configuration via Origin header"
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

    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nOrigin: http://evil.example.com\r\nUser-Agent: rustmap\r\nConnection: close\r\n\r\n"
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

    local headers = response:match("^(.-)\r\n\r\n")
    if not headers then
        return nil
    end

    local result = {}

    local acao = headers:match("[Aa]ccess%-[Cc]ontrol%-[Aa]llow%-[Oo]rigin:%s*([^\r\n]+)")
    if acao then
        result[#result + 1] = "Access-Control-Allow-Origin: " .. acao
    end

    local acac = headers:match("[Aa]ccess%-[Cc]ontrol%-[Aa]llow%-[Cc]redentials:%s*([^\r\n]+)")
    if acac then
        result[#result + 1] = "Access-Control-Allow-Credentials: " .. acac
    end

    local acam = headers:match("[Aa]ccess%-[Cc]ontrol%-[Aa]llow%-[Mm]ethods:%s*([^\r\n]+)")
    if acam then
        result[#result + 1] = "Access-Control-Allow-Methods: " .. acam
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
