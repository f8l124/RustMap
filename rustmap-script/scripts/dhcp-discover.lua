summary = "Sends DHCP DISCOVER and parses OFFER response"
categories = {"discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({67}, {"dhcps", "bootps"}, {"udp"}, nil)

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        socket:close()
        return nil
    end

    -- Build DHCP DISCOVER packet
    local xid = string.char(0x39, 0x03, 0xF3, 0x26) -- transaction ID
    local mac = string.char(0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF) -- fake MAC

    local packet = string.char(
        0x01, -- op: BOOTREQUEST
        0x01, -- htype: Ethernet
        0x06, -- hlen: 6
        0x00  -- hops
    ) .. xid ..
    string.char(
        0x00, 0x00, -- secs
        0x80, 0x00  -- flags: broadcast
    ) ..
    string.rep(string.char(0x00), 4) .. -- ciaddr
    string.rep(string.char(0x00), 4) .. -- yiaddr
    string.rep(string.char(0x00), 4) .. -- siaddr
    string.rep(string.char(0x00), 4) .. -- giaddr
    mac .. string.rep(string.char(0x00), 10) .. -- chaddr (16 bytes)
    string.rep(string.char(0x00), 64) .. -- sname
    string.rep(string.char(0x00), 128) .. -- file
    -- Magic cookie
    string.char(0x63, 0x82, 0x53, 0x63) ..
    -- Option 53: DHCP Message Type = DISCOVER (1)
    string.char(0x35, 0x01, 0x01) ..
    -- Option 55: Parameter Request List
    string.char(0x37, 0x06,
        0x01, -- Subnet Mask
        0x03, -- Router
        0x06, -- DNS
        0x0F, -- Domain Name
        0x33, -- Lease Time
        0x1C  -- Broadcast Address
    ) ..
    -- End
    string.char(0xFF)

    status, err = socket:send(packet)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or #data < 240 then
        return nil
    end

    -- Verify magic cookie at offset 236
    if string.byte(data, 237) ~= 0x63 or string.byte(data, 238) ~= 0x82 or
       string.byte(data, 239) ~= 0x53 or string.byte(data, 240) ~= 0x63 then
        return nil
    end

    local result = {}

    -- yiaddr (offered IP) at offset 17-20
    local offered_ip = string.format("%d.%d.%d.%d",
        string.byte(data, 17), string.byte(data, 18),
        string.byte(data, 19), string.byte(data, 20))
    if offered_ip ~= "0.0.0.0" then
        result[#result + 1] = "Offered: " .. offered_ip
    end

    -- siaddr (server IP) at offset 21-24
    local server_ip = string.format("%d.%d.%d.%d",
        string.byte(data, 21), string.byte(data, 22),
        string.byte(data, 23), string.byte(data, 24))
    if server_ip ~= "0.0.0.0" then
        result[#result + 1] = "Server: " .. server_ip
    end

    -- Parse DHCP options starting at offset 241
    local i = 241
    while i <= #data do
        local opt = string.byte(data, i)
        if opt == 0xFF then break end -- End
        if opt == 0x00 then -- Padding
            i = i + 1
            goto continue
        end

        if i + 1 > #data then break end
        local opt_len = string.byte(data, i + 1)
        if i + 1 + opt_len > #data then break end

        if opt == 1 and opt_len == 4 then -- Subnet Mask
            result[#result + 1] = "Mask: " .. format_ip(data, i + 2)
        elseif opt == 3 and opt_len >= 4 then -- Router
            result[#result + 1] = "Gateway: " .. format_ip(data, i + 2)
        elseif opt == 6 and opt_len >= 4 then -- DNS
            local dns = format_ip(data, i + 2)
            if opt_len >= 8 then
                dns = dns .. ", " .. format_ip(data, i + 6)
            end
            result[#result + 1] = "DNS: " .. dns
        elseif opt == 15 and opt_len > 0 then -- Domain Name
            result[#result + 1] = "Domain: " .. data:sub(i + 2, i + 1 + opt_len)
        elseif opt == 51 and opt_len == 4 then -- Lease Time
            local lease = string.byte(data, i + 2) * 16777216 +
                string.byte(data, i + 3) * 65536 +
                string.byte(data, i + 4) * 256 +
                string.byte(data, i + 5)
            result[#result + 1] = "Lease: " .. lease .. "s"
        end

        i = i + 2 + opt_len
        ::continue::
    end

    if #result == 0 then
        return nil
    end

    return "DHCP: " .. table.concat(result, "; ")
end

function format_ip(data, offset)
    return string.format("%d.%d.%d.%d",
        string.byte(data, offset),
        string.byte(data, offset + 1),
        string.byte(data, offset + 2),
        string.byte(data, offset + 3))
end
