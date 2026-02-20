summary = "Shows SSH server version and protocol banner"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({22}, {"ssh"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- SSH server sends its banner immediately on connect
    local ok, banner = socket:receive()
    socket:close()

    if not ok or not banner then
        return nil
    end

    -- Banner format: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    banner = banner:gsub("[\r\n]+$", "")

    if banner:match("^SSH%-") then
        return banner
    end

    return nil
end
