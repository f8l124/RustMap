summary = "Attempts DNS AXFR zone transfer (read-only)"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({53}, {"dns", "domain"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(10000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Determine domain to try from hostname or use reverse DNS hint
    local domain = nil
    if host.name and #host.name > 0 then
        -- Extract domain from hostname (remove first label)
        domain = host.name:match("%.(.+)")
    end

    if not domain then
        -- Fall back: try querying the DNS server for its SOA
        socket:close()
        return nil
    end

    -- Build AXFR query for the domain
    local txid = string.char(math.random(0, 255), math.random(0, 255))
    local query = ""
        .. txid               -- Transaction ID (randomized)
        .. "\x00\x00"         -- Flags: standard query
        .. "\x00\x01"         -- Questions: 1
        .. "\x00\x00"         -- Answers: 0
        .. "\x00\x00"         -- Authority: 0
        .. "\x00\x00"         -- Additional: 0

    -- Encode domain name
    for label in domain:gmatch("([^%.]+)") do
        query = query .. string.char(#label) .. label
    end
    query = query .. "\x00"    -- End of name
    query = query .. "\x00\xFC" -- Type: AXFR (252)
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

    -- Check response code (RCODE in lower 4 bits of flags byte 2)
    -- DNS header: TxID(2) + Flags(2) + QD(2) + AN(2) + NS(2) + AR(2)
    local rcode = data:byte(4)
    if not rcode then
        return nil
    end
    rcode = rcode % 16

    if rcode == 0 then
        -- Check answer count (ANCOUNT at bytes 7-8 of DNS header)
        local ancount_hi = data:byte(7) or 0
        local ancount_lo = data:byte(8) or 0
        local ancount = ancount_hi * 256 + ancount_lo

        if ancount > 0 then
            return string.format("Zone transfer allowed! %d records for %s", ancount, domain)
        else
            return "Zone transfer: response empty for " .. domain
        end
    elseif rcode == 5 then
        return "Zone transfer refused (REFUSED) for " .. domain
    elseif rcode == 9 then
        return "Zone transfer not authorized (NOTAUTH) for " .. domain
    else
        return nil
    end
end
