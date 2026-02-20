summary = "Detects SSL/TLS service on a port"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

local SSL_PORTS = {443, 465, 636, 989, 990, 993, 995, 8443}

portrule = function(host, port)
    for _, p in ipairs(SSL_PORTS) do
        if port.number == p then
            return true
        end
    end
    if port.service and port.service.name then
        local name = port.service.name
        if name == "https" or name == "ssl" or name == "imaps" or name == "pop3s" then
            return true
        end
    end
    return false
end

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read initial server response (TLS servers wait for ClientHello,
    -- so this will likely timeout for pure TLS services)
    local ok, data = socket:receive()
    socket:close()

    if ok and data and #data > 0 then
        -- Check if this looks like a TLS record
        local b1 = data:byte(1)
        if b1 and (b1 == 0x15 or b1 == 0x16 or b1 == 0x17) then
            return "TLS service detected on port " .. port.number
        end
        return "Port " .. port.number .. " responds with plaintext (may support STARTTLS)"
    end

    return "SSL/TLS likely on port " .. port.number
end
