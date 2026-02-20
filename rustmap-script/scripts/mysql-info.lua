summary = "Extracts version and capabilities from the MySQL server greeting"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({3306}, {"mysql"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- MySQL sends a handshake packet immediately on connect
    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 5 then
        return nil
    end

    -- MySQL packet format:
    -- 3 bytes: payload length (little-endian)
    -- 1 byte: sequence number
    -- Payload starts at byte 5

    local payload_start = 5
    local protocol_version = data:byte(payload_start)

    if not protocol_version then
        return nil
    end

    -- Protocol version 0xFF means error packet
    if protocol_version == 0xFF then
        -- Error packet: skip error code (2 bytes), read message
        if #data > payload_start + 2 then
            local errmsg = data:sub(payload_start + 3)
            errmsg = errmsg:gsub("[\r\n%z]+", "")
            return "Error: " .. errmsg
        end
        return nil
    end

    -- Protocol version 10 is the standard handshake
    if protocol_version ~= 10 then
        return "Protocol version: " .. tostring(protocol_version)
    end

    -- Extract null-terminated server version string
    local version_end = data:find("%z", payload_start + 1)
    if not version_end then
        return "Protocol version: 10"
    end

    local version = data:sub(payload_start + 1, version_end - 1)

    -- After version string + null terminator:
    -- 4 bytes: connection ID (little-endian)
    local id_start = version_end + 1
    local conn_id = nil
    if #data >= id_start + 3 then
        conn_id = data:byte(id_start)
            + data:byte(id_start + 1) * 256
            + data:byte(id_start + 2) * 65536
            + data:byte(id_start + 3) * 16777216
    end

    local result = version
    if conn_id then
        result = result .. " (connection id: " .. tostring(conn_id) .. ")"
    end

    return result
end
