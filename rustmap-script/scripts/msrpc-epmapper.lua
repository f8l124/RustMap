summary = "Queries MSRPC Endpoint Mapper for registered services"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({135}, {"msrpc", "epmap"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- DCE/RPC Bind request to EPMapper (e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0)
    -- This is a minimal DCE/RPC bind packet
    local bind_packet = string.char(
        -- RPC header (version 5.0, packet type 11 = bind)
        0x05, 0x00, -- version
        0x0B, -- packet type (bind)
        0x03, -- flags (first+last frag)
        0x10, 0x00, 0x00, 0x00, -- data representation (little-endian)
        0x48, 0x00, -- frag length (72)
        0x00, 0x00, -- auth length
        0x01, 0x00, 0x00, 0x00, -- call ID
        -- Bind PDU
        0xB8, 0x10, -- max xmit frag
        0xB8, 0x10, -- max recv frag
        0x00, 0x00, 0x00, 0x00, -- assoc group
        0x01, 0x00, 0x00, 0x00, -- num context items
        -- Context item
        0x00, 0x00, -- context ID
        0x01, 0x00, -- num transfer syntaxes
        -- Abstract syntax: EPMapper UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
        0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
        0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
        0x03, 0x00, 0x00, 0x00, -- version 3.0
        -- Transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00  -- version 2.0
    )

    status, err = socket:send(bind_packet)
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
        -- DCE/RPC bind_ack is typically one packet
        if #response >= 24 then break end
    end

    -- Check for bind_ack (type 0x0C)
    if #response < 24 then
        socket:close()
        return nil
    end

    local ptype = string.byte(response, 3)
    if ptype ~= 0x0C then
        socket:close()
        if ptype == 0x0D then
            return "MSRPC Endpoint Mapper: bind rejected"
        end
        return nil
    end

    local result = {}
    result[#result + 1] = "MSRPC Endpoint Mapper accessible"

    -- Extract secondary address (named pipe or port) from bind_ack
    if #response >= 26 then
        local addr_len = string.byte(response, 25) + string.byte(response, 26) * 256
        if addr_len > 0 and addr_len < 50 and #response >= 26 + addr_len then
            local addr = response:sub(27, 26 + addr_len - 1)
            if #addr > 0 then
                result[#result + 1] = "Address: " .. addr
            end
        end
    end

    socket:close()
    return table.concat(result, "; ")
end
