summary = "Tests MQTT anonymous access and reads $SYS topics"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({1883, 8883}, {"mqtt"}, nil, nil)

-- Encode MQTT remaining length (variable-length encoding per spec 3.1.1)
local function mqtt_encode_length(len)
    local result = ""
    repeat
        local b = len % 128
        len = math.floor(len / 128)
        if len > 0 then b = b + 128 end
        result = result .. string.char(b)
    until len == 0
    return result
end

-- Decode MQTT variable-length remaining length field starting at pos in data.
-- Returns (remaining_length, bytes_consumed) or (nil, 0) on error.
local function mqtt_decode_remaining(data, pos)
    local multiplier = 1
    local value = 0
    local i = pos
    repeat
        if i > #data then return nil, 0 end
        local encoded_byte = data:byte(i)
        value = value + (encoded_byte % 128) * multiplier
        multiplier = multiplier * 128
        i = i + 1
        if multiplier > 128 * 128 * 128 * 128 then return nil, 0 end -- max 4 bytes
    until encoded_byte < 128
    return value, i - pos
end

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1)
    local client_id = "rustmap-scan"
    local connect_payload = client_id

    -- Variable header: Protocol Name + Level + Connect Flags + Keep Alive
    local var_header = ""
        .. "\x00\x04MQTT" -- Protocol Name
        .. "\x04"         -- Protocol Level (3.1.1)
        .. "\x02"         -- Connect Flags: Clean Session
        .. "\x00\x3C"     -- Keep Alive: 60s

    -- Payload: Client ID (length-prefixed)
    local payload = string.char(0, #client_id) .. client_id

    local connect_body = var_header .. payload
    local connect_packet = "\x10" -- CONNECT packet type
        .. mqtt_encode_length(#connect_body)
        .. connect_body

    status, err = socket:send(connect_packet)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    if not ok or not data or #data < 4 then
        socket:close()
        return nil
    end

    -- Check CONNACK
    local pkt_type = math.floor(data:byte(1) / 16)
    if pkt_type ~= 2 then -- Not CONNACK
        socket:close()
        return nil
    end

    local return_code = data:byte(4)
    if not return_code then
        socket:close()
        return nil
    end

    local result = {}

    if return_code == 0 then
        result[#result + 1] = "Anonymous access: allowed"
    elseif return_code == 4 then
        socket:close()
        return "Anonymous access: bad credentials"
    elseif return_code == 5 then
        socket:close()
        return "Anonymous access: not authorized"
    else
        socket:close()
        return string.format("CONNACK return code: %d", return_code)
    end

    -- Try subscribing to $SYS/broker/version
    local topic = "$SYS/broker/version"
    local sub_var = "\x00\x01" -- Packet identifier: 1
    local sub_payload = string.char(0, #topic) .. topic .. "\x00" -- QoS 0
    local sub_body = sub_var .. sub_payload
    local subscribe_packet = "\x82" -- SUBSCRIBE
        .. mqtt_encode_length(#sub_body)
        .. sub_body

    status, err = socket:send(subscribe_packet)
    if not status then
        socket:close()
        return table.concat(result, "; ")
    end

    -- Read SUBACK and any published messages
    for i = 1, 3 do
        ok, data = socket:receive()
        if not ok or not data then break end

        -- Check for PUBLISH packet (type 3)
        if #data >= 2 then
            local fixed_header = data:byte(1)
            local msg_type = math.floor(fixed_header / 16)
            if msg_type == 3 then
                -- Decode variable-length remaining length
                local remaining, rem_bytes = mqtt_decode_remaining(data, 2)
                if remaining and #data >= 1 + rem_bytes + remaining then
                    local payload_start = 1 + rem_bytes + 1 -- start of variable header
                    if payload_start + 1 <= #data then
                        local topic_len = data:byte(payload_start) * 256 + data:byte(payload_start + 1)
                        if topic_len and payload_start + 1 + topic_len <= #data then
                            local data_offset = payload_start + 2 + topic_len
                            -- QoS 1 or 2: skip 2-byte packet identifier
                            local qos = math.floor(fixed_header / 2) % 4
                            if qos >= 1 then
                                data_offset = data_offset + 2
                            end
                            if data_offset <= #data then
                                local msg_payload = data:sub(data_offset)
                                if #msg_payload > 0 then
                                    result[#result + 1] = "Broker: " .. msg_payload:gsub("[\r\n]+", " ")
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    -- Send DISCONNECT
    socket:send("\xE0\x00")
    socket:close()

    return table.concat(result, "; ")
end
