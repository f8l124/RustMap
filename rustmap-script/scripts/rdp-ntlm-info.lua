summary = "RDP negotiation probe: detects supported security protocol (TLS, CredSSP/NLA)"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({3389}, {"ms-wbt-server", "rdp"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- X.224 Connection Request with RDP Negotiation Request
    -- Request CredSSP (NLA) to trigger NTLM negotiation
    local rdp_neg = ""
        .. "\x03\x00" -- TPKT version 3
        .. "\x00\x13" -- TPKT length: 19
        .. "\x0E"     -- X.224 length: 14
        .. "\xE0"     -- X.224 CR (Connection Request)
        .. "\x00\x00" -- DST-REF
        .. "\x00\x00" -- SRC-REF
        .. "\x00"     -- Class 0
        -- RDP Negotiation Request
        .. "\x01"     -- Type: Negotiation Request
        .. "\x00"     -- Flags
        .. "\x08\x00" -- Length: 8
        .. "\x03\x00\x00\x00" -- Requested protocols: CredSSP + TLS

    status, err = socket:send(rdp_neg)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    socket:close()

    if not ok or not data or #data < 11 then
        return nil
    end

    local result = {}

    -- Check if we got a Connection Confirm
    if data:byte(6) == 0xD0 then
        result[#result + 1] = "RDP Connection Confirm received"

        -- Check negotiation response
        if #data >= 19 then
            local neg_type = data:byte(12)
            if neg_type == 0x02 then
                -- Negotiation Response
                local protocol = data:byte(16)
                if protocol then
                    if protocol == 0 then
                        result[#result + 1] = "Protocol: Standard RDP"
                    elseif protocol == 1 then
                        result[#result + 1] = "Protocol: TLS"
                    elseif protocol == 2 then
                        result[#result + 1] = "Protocol: CredSSP (NLA)"
                    elseif protocol == 3 then
                        result[#result + 1] = "Protocol: CredSSP + TLS"
                    end
                end
            elseif neg_type == 0x03 then
                -- Negotiation Failure
                result[#result + 1] = "NLA not supported"
            end
        end
    elseif data:byte(6) == 0x50 then
        result[#result + 1] = "RDP: Connection rejected"
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
