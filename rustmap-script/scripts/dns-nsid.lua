summary = "Queries DNS NSID (Name Server Identifier) via EDNS0"
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

    -- Build a DNS query for version.bind CH TXT with EDNS0 NSID option
    -- This is a standard approach used by nmap's dns-nsid script
    --
    -- DNS header (12 bytes):
    --   ID=random, QR=0 OPCODE=0 RD=1, QDCOUNT=1, ARCOUNT=1
    -- Question: version.bind CH TXT
    -- Additional: OPT RR with NSID option

    local query = ""
    -- Header
    query = query .. string.char(math.random(0, 255), math.random(0, 255)) -- ID (randomized)
    query = query .. "\x01\x00" -- RD=1
    query = query .. "\x00\x01" -- QDCOUNT=1
    query = query .. "\x00\x00" -- ANCOUNT=0
    query = query .. "\x00\x00" -- NSCOUNT=0
    query = query .. "\x00\x01" -- ARCOUNT=1

    -- Question: version.bind CH TXT
    query = query .. "\x07version\x04bind\x00"
    query = query .. "\x00\x10" -- QTYPE=TXT
    query = query .. "\x00\x03" -- QCLASS=CH

    -- Additional: OPT RR with NSID option
    query = query .. "\x00"     -- Name (root)
    query = query .. "\x00\x29" -- TYPE=OPT
    query = query .. "\x10\x00" -- UDP payload size=4096
    query = query .. "\x00\x00\x00\x00" -- Extended RCODE and flags
    -- RDLENGTH=4, NSID option: code=3, length=0
    query = query .. "\x00\x04" -- RDLENGTH
    query = query .. "\x00\x03" -- Option code: NSID
    query = query .. "\x00\x00" -- Option length: 0 (request)

    -- TCP DNS: prepend 2-byte length
    local len = #query
    local tcp_msg = string.char(math.floor(len / 256), len % 256) .. query

    status, err = socket:send(tcp_msg)
    if not status then
        socket:close()
        return nil
    end

    -- Read response (TCP DNS: 2-byte length prefix + data)
    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 14 then
        return nil
    end

    -- Skip 2-byte TCP length prefix
    local offset = 3

    -- Skip DNS header (12 bytes)
    offset = offset + 12

    -- Try to find TXT record data in the response
    -- Look for version.bind TXT answer
    local result = extract_txt(data, offset)
    if result then
        return "version.bind: " .. result
    end

    return nil
end

-- Simple TXT record extraction from DNS response
function extract_txt(data, start)
    -- Scan through the response looking for TXT record data
    local i = start
    while i <= #data - 4 do
        -- Look for TXT type (0x0010) and CH class (0x0003)
        local b1, b2, b3, b4 = data:byte(i), data:byte(i + 1), data:byte(i + 2), data:byte(i + 3)
        if b1 == 0x00 and b2 == 0x10 and b3 == 0x00 and b4 == 0x03 then
            -- Found TXT CH record, skip type(2)+class(2)+TTL(4)+rdlength(2) = 10 bytes
            local txt_start = i + 10
            if txt_start <= #data then
                local txt_len = data:byte(txt_start)
                if txt_len and txt_start + txt_len <= #data then
                    return data:sub(txt_start + 1, txt_start + txt_len)
                end
            end
        end
        i = i + 1
    end
    return nil
end
