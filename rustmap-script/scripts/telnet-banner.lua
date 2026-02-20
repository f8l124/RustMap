summary = "Grabs the Telnet banner and negotiation info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({23, 2323}, {"telnet"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Read initial data (may contain Telnet negotiation + banner)
    local ok, data = socket:receive()
    if not ok or not data or #data == 0 then
        socket:close()
        return nil
    end

    -- Telnet negotiation uses IAC (0xFF) sequences
    -- Strip them to find the readable banner text
    local banner = strip_telnet_commands(data)

    -- If we only got negotiation bytes, try reading again
    -- Some servers send banner after initial negotiation
    if #banner == 0 then
        -- Send a basic "will" response to common negotiations to coax a banner
        -- WILL TERMINAL-TYPE (0x18), WILL WINDOW-SIZE (0x1F)
        socket:send("\xFF\xFB\x18\xFF\xFB\x1F")

        ok, data = socket:receive()
        if ok and data then
            banner = strip_telnet_commands(data)
        end
    end

    socket:close()

    if #banner == 0 then
        return nil
    end

    -- Clean up the banner text
    banner = banner:gsub("[\r\n]+$", "")
    banner = banner:gsub("^[\r\n]+", "")

    -- Limit length
    if #banner > 512 then
        banner = banner:sub(1, 512) .. "..."
    end

    if #banner > 0 then
        return banner
    end

    return nil
end

-- Strip Telnet IAC command sequences from data, returning only printable text
function strip_telnet_commands(data)
    local result = ""
    local i = 1
    while i <= #data do
        local b = data:byte(i)
        if b == 0xFF and i + 1 <= #data then
            local cmd = data:byte(i + 1)
            if cmd == 0xFF then
                -- Escaped 0xFF = literal 0xFF
                result = result .. "\xFF"
                i = i + 2
            elseif cmd >= 0xFB and cmd <= 0xFE then
                -- WILL/WONT/DO/DONT + option byte
                i = i + 3
            elseif cmd == 0xFA then
                -- Sub-negotiation: skip until IAC SE (0xFF 0xF0)
                i = i + 2
                while i + 1 <= #data do
                    if data:byte(i) == 0xFF and data:byte(i + 1) == 0xF0 then
                        i = i + 2
                        break
                    end
                    i = i + 1
                end
            else
                -- Other 2-byte command
                i = i + 2
            end
        else
            -- Regular character
            if b >= 0x20 and b < 0x7F or b == 0x0A or b == 0x0D or b == 0x09 then
                result = result .. string.char(b)
            end
            i = i + 1
        end
    end
    return result
end
