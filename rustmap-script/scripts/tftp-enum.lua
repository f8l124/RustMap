summary = "Enumerates files accessible via TFTP"
categories = {"discovery", "intrusive"}
phases = {"portrule"}

portrule = shortport.port_or_service({69}, {"tftp"}, {"udp"}, nil)

function action(host, port)
    local filenames = {
        "running-config",
        "startup-config",
        "network-confg",
        "router-confg",
        "switch-confg",
        "system-config",
        "default.cfg",
        "config.txt",
        "pxelinux.0",
        "pxelinux.cfg/default",
        "boot.ini",
        "autoexec.bat",
    }

    local found = {}

    for _, filename in ipairs(filenames) do
        local socket = nmap.new_udp_socket()
        socket:set_timeout(3000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto next_file
        end

        -- Build TFTP RRQ (opcode 0x0001)
        local request = string.char(0x00, 0x01) .. -- opcode: RRQ
            filename .. string.char(0x00) ..        -- filename (null-terminated)
            "octet" .. string.char(0x00)             -- mode (null-terminated)

        status, err = socket:send(request)
        if not status then
            socket:close()
            goto next_file
        end

        local ok, data = socket:receive()
        socket:close()

        if ok and #data >= 4 then
            local opcode = string.byte(data, 1) * 256 + string.byte(data, 2)
            if opcode == 3 then -- DATA opcode
                local data_len = #data - 4
                found[#found + 1] = filename .. " (" .. data_len .. " bytes)"
            elseif opcode == 6 then -- OACK (option acknowledgment)
                found[#found + 1] = filename .. " (accessible)"
            end
            -- opcode 5 = ERROR, skip
        end

        ::next_file::
    end

    if #found == 0 then
        return nil
    end

    return "TFTP accessible files: " .. table.concat(found, ", ")
end
