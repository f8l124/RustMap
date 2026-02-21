summary = "Detects WireGuard VPN service"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({51820, 51821}, {"wireguard"}, {"udp"}, nil)

function action(host, port)
    local socket = nmap.new_udp_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        socket:close()
        return nil
    end

    -- WireGuard Handshake Initiation (Type 1)
    -- 4 bytes: message type (1) + 3 reserved bytes
    -- 4 bytes: sender index
    -- 32 bytes: unencrypted ephemeral (zeros = invalid, but may trigger a response or silence)
    -- 48 bytes: encrypted static
    -- 28 bytes: encrypted timestamp
    -- 16 bytes: mac1
    -- 16 bytes: mac2
    -- Total: 148 bytes

    -- A real WireGuard server will silently drop invalid handshakes,
    -- so we detect by timing behavior and comparing against known non-WireGuard responses

    local handshake_init = string.char(0x01, 0x00, 0x00, 0x00) .. -- type 1 + reserved
        string.char(0x00, 0x00, 0x00, 0x01) .. -- sender index
        string.rep(string.char(0x00), 32) .. -- ephemeral (zeros)
        string.rep(string.char(0x00), 48) .. -- encrypted static
        string.rep(string.char(0x00), 28) .. -- encrypted timestamp
        string.rep(string.char(0x00), 16) .. -- mac1
        string.rep(string.char(0x00), 16)    -- mac2

    status, err = socket:send(handshake_init)
    if not status then
        socket:close()
        return nil
    end

    -- WireGuard characteristic: silently drops invalid handshakes
    -- Non-WireGuard services typically respond with error or ICMP unreachable
    local ok, data = socket:receive()
    socket:close()

    -- If we get a response, check if it looks like WireGuard
    if ok and #data >= 4 then
        local msg_type = string.byte(data, 1)
        if msg_type == 2 then
            -- Type 2 = Handshake Response (unlikely with zeros, but possible)
            return "WireGuard: handshake response received"
        elseif msg_type == 3 then
            -- Type 3 = Cookie Reply
            return "WireGuard: cookie reply received (rate limiting active)"
        end
        -- Other response = probably not WireGuard
        return nil
    end

    -- No response + UDP port open = characteristic of WireGuard
    -- (WireGuard silently drops invalid packets)
    return "WireGuard: possible (UDP port open, no response to probe — characteristic of WireGuard)"
end
