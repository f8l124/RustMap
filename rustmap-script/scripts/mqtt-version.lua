summary = "Extracts MQTT broker version from CONNACK and $SYS"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({1883}, {"mqtt"}, nil, nil)

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

    -- MQTT CONNECT
    local client_id = "rustmap"
    local var_header = "\x00\x04MQTT\x04\x02\x00\x1E" -- MQTT 3.1.1, clean session, 30s keepalive
    local payload = string.char(0, #client_id) .. client_id
    local body = var_header .. payload
    local connect = "\x10" .. mqtt_encode_length(#body) .. body

    status, err = socket:send(connect)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    if not ok or not data or #data < 4 then
        socket:close()
        return nil
    end

    local pkt_type = math.floor(data:byte(1) / 16)
    if pkt_type ~= 2 then
        socket:close()
        return nil
    end

    local return_code = data:byte(4)
    if return_code ~= 0 then
        socket:close()
        if return_code == 5 then
            return "MQTT: authentication required"
        end
        return nil
    end

    local result = {"MQTT broker detected"}

    -- Subscribe to $SYS topics for version info
    local topics = {"$SYS/broker/version", "$SYS/broker/uptime", "$SYS/broker/clients/connected"}

    for _, topic in ipairs(topics) do
        local sub_var = "\x00\x01"
        local sub_payload = string.char(0, #topic) .. topic .. "\x00"
        local sub_body = sub_var .. sub_payload
        local subscribe = "\x82" .. mqtt_encode_length(#sub_body) .. sub_body

        socket:send(subscribe)
    end

    -- Read responses
    for i = 1, 5 do
        ok, data = socket:receive()
        if not ok or not data then break end

        if #data >= 2 then
            local fixed_header = data:byte(1)
            local msg_type = math.floor(fixed_header / 16)
            if msg_type == 3 then -- PUBLISH
                local remaining, rem_bytes = mqtt_decode_remaining(data, 2)
                if remaining and #data >= 1 + rem_bytes + remaining then
                    local payload_start = 1 + rem_bytes + 1 -- start of variable header
                    if payload_start + 1 <= #data then
                        local topic_len = data:byte(payload_start) * 256 + data:byte(payload_start + 1)
                        if topic_len and payload_start + 1 + topic_len <= #data then
                            local pub_topic = data:sub(payload_start + 2, payload_start + 1 + topic_len)
                            local data_offset = payload_start + 2 + topic_len
                            -- QoS 1 or 2: skip 2-byte packet identifier
                            local qos = math.floor(fixed_header / 2) % 4
                            if qos >= 1 then
                                data_offset = data_offset + 2
                            end
                            if data_offset <= #data then
                                local pub_payload = data:sub(data_offset)
                                if #pub_payload > 0 then
                                    pub_payload = pub_payload:gsub("[\r\n]+", " ")
                                    if pub_topic:match("version") then
                                        result[#result + 1] = "Version: " .. pub_payload
                                    elseif pub_topic:match("uptime") then
                                        result[#result + 1] = "Uptime: " .. pub_payload
                                    elseif pub_topic:match("clients") then
                                        result[#result + 1] = "Clients: " .. pub_payload
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    socket:send("\xE0\x00")
    socket:close()

    return table.concat(result, "; ")
end
