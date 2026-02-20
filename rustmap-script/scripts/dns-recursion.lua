summary = "Tests if DNS server allows recursive queries"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({53}, {"dns", "domain"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- DNS query for example.com A record with RD (Recursion Desired) flag set
    local txid = string.char(math.random(0, 255), math.random(0, 255))
    local query = ""
        .. txid               -- Transaction ID (randomized)
        .. "\x01\x00"         -- Flags: RD=1 (recursion desired)
        .. "\x00\x01"         -- Questions: 1
        .. "\x00\x00"         -- Answers: 0
        .. "\x00\x00"         -- Authority: 0
        .. "\x00\x00"         -- Additional: 0
        -- Question: example.com A IN
        .. "\x07example\x03com\x00"
        .. "\x00\x01"         -- Type: A
        .. "\x00\x01"         -- Class: IN

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

    if not ok2 or not data or #data < 4 then
        return nil
    end

    -- DNS header: TxID(2) + Flags(2) — no TCP prefix, we already consumed it
    local flags_hi = data:byte(3) -- first flags byte
    local flags_lo = data:byte(4) -- second flags byte

    if not flags_hi or not flags_lo then
        return nil
    end

    -- Check RA (Recursion Available) flag: bit 7 of flags_lo byte
    local ra = math.floor(flags_lo / 128) % 2

    if ra == 1 then
        return "Recursion: enabled (RA flag set)"
    else
        return "Recursion: disabled"
    end
end
