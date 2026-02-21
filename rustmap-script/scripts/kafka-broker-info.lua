summary = "Queries Kafka broker for API versions and cluster info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({9092, 9093}, {"kafka"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Kafka ApiVersions Request (API key 18, version 0)
    -- Request header: api_key(2) + api_version(2) + correlation_id(4) + client_id
    local client_id = "rustmap"
    local request_header = string.char(
        0x00, 0x12, -- api_key: ApiVersions (18)
        0x00, 0x00, -- api_version: 0
        0x00, 0x00, 0x00, 0x01 -- correlation_id: 1
    ) ..
    -- client_id (nullable string: length(2) + data)
    string.char(0x00, #client_id) .. client_id

    -- Kafka wire format: length(4) + request
    local msg_len = #request_header
    local packet = string.char(
        math.floor(msg_len / 16777216) % 256,
        math.floor(msg_len / 65536) % 256,
        math.floor(msg_len / 256) % 256,
        msg_len % 256
    ) .. request_header

    status, err = socket:send(packet)
    if not status then
        socket:close()
        return nil
    end

    local max_response_size = 65536
    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if #response > max_response_size then break end
        -- Kafka responses are typically complete in one recv
        if #response >= 8 then break end
    end
    socket:close()

    if #response < 8 then
        return nil
    end

    -- Parse response: length(4) + correlation_id(4) + error_code(2) + api_count(4)
    local resp_len = string.byte(response, 1) * 16777216 +
        string.byte(response, 2) * 65536 +
        string.byte(response, 3) * 256 +
        string.byte(response, 4)

    if resp_len < 4 then
        return nil
    end

    -- Check correlation ID matches
    local corr_id = string.byte(response, 5) * 16777216 +
        string.byte(response, 6) * 65536 +
        string.byte(response, 7) * 256 +
        string.byte(response, 8)

    if corr_id ~= 1 then
        return nil
    end

    local result = {}
    result[#result + 1] = "Kafka broker detected"

    -- Error code at offset 9-10
    if #response >= 10 then
        local error_code = string.byte(response, 9) * 256 + string.byte(response, 10)
        if error_code ~= 0 then
            result[#result + 1] = "Error: " .. error_code
            return table.concat(result, "; ")
        end
    end

    -- API count at offset 11-14
    if #response >= 14 then
        local api_count = string.byte(response, 11) * 16777216 +
            string.byte(response, 12) * 65536 +
            string.byte(response, 13) * 256 +
            string.byte(response, 14)
        result[#result + 1] = "Supported APIs: " .. api_count
    end

    return table.concat(result, "; ")
end
