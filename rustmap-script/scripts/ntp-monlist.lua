summary = "Queries NTP monlist to check for amplification risk"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = function(host, port)
    return port.number == 123 and port.protocol == "udp"
end

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- NTP private mode request for MON_GETLIST_1 (opcode 42)
    -- Byte 0: Response=0, More=0, VN=2, Mode=7 (private)
    -- Byte 1: Auth=0, Sequence=0
    -- Byte 2: Implementation=3 (IMPL_XNTPD)
    -- Byte 3: Request code=42 (REQ_MON_GETLIST_1)
    local monlist_req = "\x17" -- VN=2, Mode=7
        .. "\x00"              -- Sequence
        .. "\x03"              -- Implementation: XNTPD
        .. "\x2A"              -- Request: MON_GETLIST_1
        .. string.rep("\x00", 44) -- Padding to 48 bytes

    status, err = socket:send(monlist_req)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 4 then
        return nil
    end

    -- Check response
    local byte0 = data:byte(1)
    local mode = byte0 % 8

    if mode ~= 7 then
        -- Not a private mode response
        return nil
    end

    -- Check if we got error or data
    local byte3 = data:byte(4)
    if not byte3 then
        return nil
    end

    -- If request code matches and we got data, monlist is enabled
    if byte3 == 42 and #data > 8 then
        local resp_size = #data
        local amplification = string.format("%.1fx", resp_size / 48)
        return string.format("monlist ENABLED - %d byte response (%s amplification)", resp_size, amplification)
    elseif #data >= 4 then
        -- Check for error response
        local err_code = math.floor(data:byte(2) / 16) % 8
        if err_code > 0 then
            return nil -- monlist denied or not implemented
        end
    end

    return nil
end
