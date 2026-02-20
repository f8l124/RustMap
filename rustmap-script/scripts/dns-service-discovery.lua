summary = "Queries DNS-SD service types via _services._dns-sd._udp"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({53}, {"dns", "domain"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    local domain = "local"
    if host.name and #host.name > 0 then
        local d = host.name:match("%.(.+)")
        if d then domain = d end
    end

    -- DNS query for _services._dns-sd._udp.<domain> PTR
    local txid = string.char(math.random(0, 255), math.random(0, 255))
    local query = ""
        .. txid               -- Transaction ID (randomized)
        .. "\x01\x00"         -- Flags: RD=1
        .. "\x00\x01"         -- Questions: 1
        .. "\x00\x00"         -- Answers: 0
        .. "\x00\x00"         -- Authority: 0
        .. "\x00\x00"         -- Additional: 0

    -- Encode _services._dns-sd._udp.<domain>
    local labels = {"_services", "_dns-sd", "_udp"}
    for _, label in ipairs(labels) do
        query = query .. string.char(#label) .. label
    end
    for label in domain:gmatch("([^%.]+)") do
        query = query .. string.char(#label) .. label
    end
    query = query .. "\x00"    -- End of name
    query = query .. "\x00\x0C" -- Type: PTR (12)
    query = query .. "\x00\x01" -- Class: IN

    -- TCP DNS: prepend 2-byte length
    local len = #query
    local tcp_msg = string.char(math.floor(len / 256), len % 256) .. query

    status, err = socket:send(tcp_msg)
    if not status then
        socket:close()
        return nil
    end

    -- TCP DNS: read 2-byte length prefix, then the full DNS message
    local ok, len_data = socket:receive_bytes(2)
    if not ok or not len_data or #len_data < 2 then
        socket:close()
        return nil
    end

    local msg_len = len_data:byte(1) * 256 + len_data:byte(2)
    if msg_len < 12 or msg_len > 65535 then
        socket:close()
        return nil
    end

    local ok2, data = socket:receive_bytes(msg_len)
    socket:close()

    if not ok2 or not data or #data < 6 then
        return nil
    end

    -- Check answer count (ANCOUNT at bytes 7-8 of DNS header, no TCP prefix)
    local ancount_hi = data:byte(7) or 0
    local ancount_lo = data:byte(8) or 0
    local ancount = ancount_hi * 256 + ancount_lo

    if ancount == 0 then
        return nil
    end

    -- Try to extract service type names from PTR responses
    local services = {}
    -- Simple extraction: look for _<name>._<proto> patterns in response
    for svc in data:gmatch("(_[%w%-]+%._[%w]+)") do
        -- Deduplicate
        local found = false
        for _, existing in ipairs(services) do
            if existing == svc then found = true; break end
        end
        if not found then
            services[#services + 1] = svc
        end
    end

    if #services == 0 then
        return string.format("DNS-SD: %d service types found", ancount)
    end

    return "DNS-SD services: " .. table.concat(services, ", ")
end
