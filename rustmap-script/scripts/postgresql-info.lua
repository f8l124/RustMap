summary = "Detects PostgreSQL version from startup response"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({5432}, {"postgresql", "postgres"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- PostgreSQL startup message (protocol version 3.0)
    -- Length(4) + Protocol(4) + "user\0value\0\0"
    local user = "rustmap"
    local params = "user\x00" .. user .. "\x00\x00"
    local msg_len = 4 + 4 + #params
    local startup = string.char(
        math.floor(msg_len / 16777216) % 256,
        math.floor(msg_len / 65536) % 256,
        math.floor(msg_len / 256) % 256,
        msg_len % 256
    )
    .. "\x00\x03\x00\x00" -- Protocol 3.0
    .. params

    status, err = socket:send(startup)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 1 then
        return nil
    end

    local result = {}

    -- First byte indicates message type
    local msg_type = data:byte(1)

    if msg_type == 0x52 then
        -- 'R' = Authentication request - server is PostgreSQL
        result[#result + 1] = "PostgreSQL detected"

        -- Check auth type (4 bytes after length)
        if #data >= 9 then
            local auth_type = data:byte(9)
            if auth_type == 0 then
                result[#result + 1] = "Auth: trust (no password)"
            elseif auth_type == 3 then
                result[#result + 1] = "Auth: cleartext password"
            elseif auth_type == 5 then
                result[#result + 1] = "Auth: MD5 password"
            elseif auth_type == 10 then
                result[#result + 1] = "Auth: SASL"
            end
        end
    elseif msg_type == 0x45 then
        -- 'E' = Error response - extract message
        local msg = data:match("M([^\x00]+)")
        if msg then
            result[#result + 1] = "PostgreSQL: " .. msg
        end
    else
        return nil
    end

    -- Look for version in ParameterStatus messages (message type 'S', 0x53)
    -- The server_version parameter is sent as: 'S' + int32 len + "server_version\0" + "version_string\0"
    -- We specifically look for "server_version" to avoid matching arbitrary version-like strings.
    local sv_version = data:match("server_version%z([%d%.]+)")
    if sv_version then
        result[#result + 1] = "Version: " .. sv_version
    else
        -- Fallback: try to extract version from error messages containing "PostgreSQL"
        local pg_version = data:match("PostgreSQL (%d+%.%d+[%.%d]*)")
        if pg_version then
            result[#result + 1] = "Version: " .. pg_version
        end
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
