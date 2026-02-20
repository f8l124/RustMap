summary = "Grabs the initial banner from any open TCP port"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = function(host, port)
    return port.state == "open" and port.protocol == "tcp"
end

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Many services send a banner immediately on connect
    local ok, banner = socket:receive()
    socket:close()

    if not ok or not banner or #banner == 0 then
        return nil
    end

    -- Strip trailing whitespace and control characters
    banner = banner:gsub("[\r\n]+$", "")

    -- Limit to first line and reasonable length
    local first_line = banner:match("^([^\r\n]*)")
    if first_line and #first_line > 0 then
        if #first_line > 256 then
            first_line = first_line:sub(1, 256) .. "..."
        end
        return first_line
    end

    return nil
end
