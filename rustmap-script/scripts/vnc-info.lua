summary = "Reads VNC protocol version and security types"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service(
    {5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910},
    {"vnc"},
    nil, nil
)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- VNC server sends protocol version on connect
    local ok, data = socket:receive()
    if not ok or not data or #data < 12 then
        socket:close()
        return nil
    end

    -- Parse "RFB XXX.YYY\n"
    local version = data:match("^RFB (%d+%.%d+)")
    if not version then
        socket:close()
        return nil
    end

    local result = {"Protocol: RFB " .. version}

    -- Send our version back — echo server's version for best compatibility
    -- Use server version if <= 3.8, cap at 3.8 if higher
    local major, minor = version:match("(%d+)%.(%d+)")
    local our_version
    if major and minor and (tonumber(major) > 3 or (tonumber(major) == 3 and tonumber(minor) > 8)) then
        our_version = "RFB 003.008\n"
    else
        our_version = data:sub(1, 12)  -- Echo server's exact version string
    end
    status, err = socket:send(our_version)
    if not status then
        socket:close()
        return table.concat(result, "; ")
    end

    -- Read security types
    ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 1 then
        return table.concat(result, "; ")
    end

    -- RFB 3.8+: first byte is count of security types
    local num_types = data:byte(1)
    if not num_types or num_types == 0 then
        -- num_types=0 means connection failed, next 4 bytes = reason length
        if #data >= 5 then
            local reason_len = data:byte(2) * 16777216 + data:byte(3) * 65536 + data:byte(4) * 256 + data:byte(5)
            if reason_len > 0 and reason_len < 256 and #data >= 5 + reason_len then
                result[#result + 1] = "Error: " .. data:sub(6, 5 + reason_len)
            end
        end
        return table.concat(result, "; ")
    end

    local sec_types = {}
    local sec_names = {
        [0] = "Invalid",
        [1] = "None",
        [2] = "VNC Authentication",
        [5] = "RA2",
        [6] = "RA2ne",
        [16] = "Tight",
        [17] = "Ultra",
        [18] = "TLS",
        [19] = "VeNCrypt",
        [20] = "GTK-VNC SASL",
        [21] = "MD5 Hash",
        [22] = "Colin Dean xvp",
        [30] = "Apple Remote Desktop",
    }

    for i = 1, num_types do
        if i + 1 <= #data then
            local sec_type = data:byte(i + 1)
            if sec_type then
                local name = sec_names[sec_type] or string.format("Type %d", sec_type)
                sec_types[#sec_types + 1] = name
            end
        end
    end

    if #sec_types > 0 then
        result[#result + 1] = "Security: " .. table.concat(sec_types, ", ")
    end

    return table.concat(result, "; ")
end
