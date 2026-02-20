summary = "PPTP Start-Control-Connection - firmware and hostname"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({1723}, {"pptp"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- PPTP Start-Control-Connection-Request
    -- Length: 156 bytes, Message Type: 1 (Control), Magic Cookie: 0x1A2B3C4D
    -- Control Message Type: 1 (Start-Control-Connection-Request)
    local pptp_req = ""
        .. "\x00\x9C"         -- Length: 156
        .. "\x00\x01"         -- Message Type: Control
        .. "\x1A\x2B\x3C\x4D" -- Magic Cookie
        .. "\x00\x01"         -- Control Message Type: Start-Control-Connection-Request
        .. "\x00\x00"         -- Reserved
        .. "\x01\x00"         -- Protocol Version: 1.0
        .. "\x00\x00"         -- Reserved
        .. "\x00\x00\x00\x01" -- Framing Capabilities
        .. "\x00\x00\x00\x01" -- Bearer Capabilities
        .. "\x00\x00"         -- Maximum Channels
        .. "\x00\x01"         -- Firmware Revision
        -- Hostname (64 bytes, null-padded)
        .. "rustmap" .. string.rep("\x00", 57)
        -- Vendor String (64 bytes, null-padded)
        .. "RustMap Scanner" .. string.rep("\x00", 49)

    status, err = socket:send(pptp_req)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 28 then
        return nil
    end

    -- Verify Magic Cookie
    if data:sub(5, 8) ~= "\x1A\x2B\x3C\x4D" then
        return nil
    end

    -- Check Control Message Type: should be 2 (Start-Control-Connection-Reply)
    local msg_type_hi = data:byte(9)
    local msg_type_lo = data:byte(10)
    if not msg_type_hi or not msg_type_lo then
        return nil
    end
    local msg_type = msg_type_hi * 256 + msg_type_lo
    if msg_type ~= 2 then
        return nil
    end

    -- Check Result Code (bytes 15-16): 1 = General OK
    if #data >= 16 then
        local rc = data:byte(15) * 256 + data:byte(16)
        if rc ~= 1 then
            return "PPTP: connection refused (result code " .. rc .. ")"
        end
    end

    local result = {}

    -- Reply offsets per RFC 2637 Start-Control-Connection-Reply:
    -- 13-14: Protocol Version, 15-16: Result Code, 17: Error Code,
    -- 18-20: Reserved1, 21-24: Framing Caps, 25-28: Bearer Caps,
    -- 29-30: Max Channels, 31-32: Firmware Revision,
    -- 33-96: Hostname (64 bytes), 97-160: Vendor (64 bytes)

    -- Protocol Version (bytes 13-14)
    if #data >= 14 then
        local ver_major = data:byte(13)
        local ver_minor = data:byte(14)
        if ver_major and ver_minor then
            result[#result + 1] = string.format("PPTP %d.%d", ver_major, ver_minor)
        end
    end

    -- Firmware Revision (bytes 31-32)
    if #data >= 32 then
        local fw_hi = data:byte(31)
        local fw_lo = data:byte(32)
        if fw_hi and fw_lo then
            result[#result + 1] = string.format("Firmware: %d.%d", fw_hi, fw_lo)
        end
    end

    -- Hostname (bytes 33-96, 64 bytes null-padded)
    if #data >= 96 then
        local hostname = data:sub(33, 96):gsub("\x00+$", "")
        if #hostname > 0 then
            result[#result + 1] = "Hostname: " .. hostname
        end
    end

    -- Vendor (bytes 97-160, 64 bytes null-padded)
    if #data >= 160 then
        local vendor = data:sub(97, 160):gsub("\x00+$", "")
        if #vendor > 0 then
            result[#result + 1] = "Vendor: " .. vendor
        end
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
