summary = "Detects OpenVPN service via reset packet"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({1194, 443}, {"openvpn"}, {"udp"}, nil)

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        socket:close()
        return nil
    end

    -- OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet
    -- Opcode: 0x38 (P_CONTROL_HARD_RESET_CLIENT_V2 = 7 << 3, key_id = 0)
    -- Session ID: 8 bytes (random-ish)
    -- HMAC: not included (pre-shared key not known)
    -- Packet ID: 4 bytes
    -- Ack array length: 1 byte (0 = no acks)
    -- Remote session ID: not included when ack=0
    -- Message packet ID: 4 bytes

    local session_id = string.char(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
    local packet = string.char(0x38) .. -- opcode: P_CONTROL_HARD_RESET_CLIENT_V2
        session_id ..
        string.char(0x00) .. -- HMAC placeholder (not valid, but OpenVPN will respond)
        string.char(0x00, 0x00, 0x00, 0x01) .. -- packet ID
        string.char(0x00) .. -- ack array length = 0
        string.char(0x00, 0x00, 0x00, 0x00) -- message packet ID

    status, err = socket:send(packet)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or #data < 2 then
        return nil
    end

    -- Check for OpenVPN server reset response
    -- P_CONTROL_HARD_RESET_SERVER_V2 opcode = 0x40 (8 << 3)
    local opcode = string.byte(data, 1)
    local op_type = math.floor(opcode / 8) -- high 5 bits

    if op_type == 8 then
        -- P_CONTROL_HARD_RESET_SERVER_V2
        local result = "OpenVPN detected (server reset response)"

        -- Extract server session ID (bytes 2-9)
        if #data >= 9 then
            local sid = string.format("%02X%02X%02X%02X%02X%02X%02X%02X",
                string.byte(data, 2), string.byte(data, 3),
                string.byte(data, 4), string.byte(data, 5),
                string.byte(data, 6), string.byte(data, 7),
                string.byte(data, 8), string.byte(data, 9))
            result = result .. "; Session: " .. sid
        end

        return result
    elseif op_type == 7 then
        -- Echoed back? Unusual but possible with some configs
        return "OpenVPN: possible (echoed reset packet)"
    end

    return nil
end
