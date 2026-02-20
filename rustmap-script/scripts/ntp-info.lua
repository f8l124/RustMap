summary = "NTP mode 3 query - stratum, reference ID, server time"
categories = {"default", "safe", "discovery"}
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

    -- NTP Client Request (Mode 3, Version 4)
    -- Byte 0: LI=0, VN=4, Mode=3 => 0x23
    local ntp_request = "\x23" -- LI=0, VN=4, Mode=3
        .. "\x00"              -- Stratum
        .. "\x06"              -- Poll interval
        .. "\xEC"              -- Precision
        .. "\x00\x00\x00\x00" -- Root delay
        .. "\x00\x00\x00\x00" -- Root dispersion
        .. "\x00\x00\x00\x00" -- Reference ID
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Reference timestamp
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Origin timestamp
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Receive timestamp
        .. "\x00\x00\x00\x00\x00\x00\x00\x00" -- Transmit timestamp

    status, err = socket:send(ntp_request)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 48 then
        return nil
    end

    local result = {}

    -- Byte 0: LI(2), VN(3), Mode(3)
    local byte0 = data:byte(1)
    local li = math.floor(byte0 / 64)
    local vn = math.floor(byte0 / 8) % 8
    local mode = byte0 % 8

    result[#result + 1] = string.format("NTPv%d, Mode %d", vn, mode)

    -- Byte 1: Stratum
    local stratum = data:byte(2)
    if stratum then
        local stratum_desc = ""
        if stratum == 0 then
            stratum_desc = " (unspecified)"
        elseif stratum == 1 then
            stratum_desc = " (primary reference)"
        elseif stratum <= 15 then
            stratum_desc = " (secondary reference)"
        elseif stratum == 16 then
            stratum_desc = " (unsynchronized)"
        end
        result[#result + 1] = "Stratum: " .. stratum .. stratum_desc
    end

    -- Bytes 12-15: Reference ID
    if stratum and stratum <= 1 then
        -- Reference ID is a 4-char ASCII string for stratum 0-1
        local ref_id = ""
        for i = 13, 16 do
            local c = data:byte(i)
            if c and c >= 32 and c <= 126 then
                ref_id = ref_id .. string.char(c)
            end
        end
        if #ref_id > 0 then
            result[#result + 1] = "Reference: " .. ref_id
        end
    else
        -- Reference ID is IP address for stratum >= 2
        if #data >= 16 then
            result[#result + 1] = string.format("Reference: %d.%d.%d.%d",
                data:byte(13), data:byte(14), data:byte(15), data:byte(16))
        end
    end

    -- Bytes 40-47: Transmit timestamp (NTP epoch: 1900-01-01)
    if #data >= 44 then
        local seconds = 0
        for i = 41, 44 do
            seconds = seconds * 256 + data:byte(i)
        end
        -- Convert NTP timestamp to Unix (subtract 70 years worth of seconds)
        local unix_time = seconds - 2208988800
        if unix_time > 0 then
            result[#result + 1] = "Server time: " .. os.date("!%Y-%m-%d %H:%M:%S UTC", unix_time)
        end
    end

    -- Leap indicator
    if li == 3 then
        result[#result + 1] = "Clock: unsynchronized (leap indicator alarm)"
    end

    return table.concat(result, "; ")
end
