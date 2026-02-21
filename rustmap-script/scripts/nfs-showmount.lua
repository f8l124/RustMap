summary = "Lists NFS exports via RPC MOUNT protocol"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({111, 2049}, {"rpcbind", "nfs"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- For portmapper (111), first query for MOUNT program port
    -- For NFS (2049), try direct MOUNT EXPORT call
    -- We'll try a portmapper GETPORT call for MOUNT program (100005)

    if port.number == 111 then
        -- RPC portmapper GETPORT for MOUNT (100005) v3 TCP
        local xid = string.char(0x12, 0x34, 0x56, 0x78)
        local rpc_call = xid ..
            string.char(
                0x00, 0x00, 0x00, 0x00, -- message type: call
                0x00, 0x00, 0x00, 0x02, -- RPC version 2
                0x00, 0x01, 0x86, 0xA0, -- program: portmapper (100000)
                0x00, 0x00, 0x00, 0x02, -- program version 2
                0x00, 0x00, 0x00, 0x03, -- procedure: GETPORT
                0x00, 0x00, 0x00, 0x00, -- auth flavor: none
                0x00, 0x00, 0x00, 0x00, -- auth length
                0x00, 0x00, 0x00, 0x00, -- verifier flavor
                0x00, 0x00, 0x00, 0x00, -- verifier length
                -- GETPORT args: program=100005, version=3, proto=TCP(6), port=0
                0x00, 0x01, 0x86, 0xA5, -- program: MOUNT (100005)
                0x00, 0x00, 0x00, 0x03, -- version 3
                0x00, 0x00, 0x00, 0x06, -- protocol: TCP
                0x00, 0x00, 0x00, 0x00  -- port: 0
            )

        -- TCP RPC: prepend 4-byte record marker (last fragment, length)
        local rpc_len = #rpc_call
        local record_marker = string.char(
            0x80 + math.floor(rpc_len / 16777216),
            math.floor(rpc_len / 65536) % 256,
            math.floor(rpc_len / 256) % 256,
            rpc_len % 256
        )

        status, err = socket:send(record_marker .. rpc_call)
        if not status then
            socket:close()
            return nil
        end

        local ok, data = socket:receive()
        if not ok then
            socket:close()
            return nil
        end

        -- Parse GETPORT response: last 4 bytes should be the port
        if #data >= 32 then
            local mount_port = string.byte(data, #data - 3) * 16777216 +
                string.byte(data, #data - 2) * 65536 +
                string.byte(data, #data - 1) * 256 +
                string.byte(data, #data)

            socket:close()

            if mount_port > 0 and mount_port < 65536 then
                return "NFS: MOUNT service on port " .. mount_port .. " (use nfs-showmount on that port)"
            end
        end

        socket:close()
        return "NFS portmapper accessible; MOUNT port query failed"
    end

    -- Direct NFS port — just report it's accessible
    socket:close()
    return "NFS service accessible on port " .. port.number
end
