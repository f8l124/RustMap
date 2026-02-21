summary = "Checks for known SSL/TLS weaknesses and vulnerabilities"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({443, 8443, 993, 995, 465, 636}, {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps"}, nil, nil)

function action(host, port)
    local warnings = {}

    -- Test 1: SSLv3 support (POODLE vulnerability)
    if test_protocol(host, port, 0x03, 0x00) then
        warnings[#warnings + 1] = "SSLv3 supported (POODLE CVE-2014-3566)"
    end

    -- Test 2: TLS 1.0 (deprecated)
    if test_protocol(host, port, 0x03, 0x01) then
        warnings[#warnings + 1] = "TLS 1.0 supported (deprecated)"
    end

    -- Test 3: TLS 1.1 (deprecated)
    if test_protocol(host, port, 0x03, 0x02) then
        warnings[#warnings + 1] = "TLS 1.1 supported (deprecated)"
    end

    -- Test 4: RC4 cipher support
    if test_cipher(host, port, 0x00, 0x05) then
        warnings[#warnings + 1] = "RC4 cipher supported (RFC 7465)"
    end

    -- Test 5: NULL cipher support
    if test_cipher(host, port, 0x00, 0x02) then
        warnings[#warnings + 1] = "NULL cipher supported (no encryption)"
    end

    -- Test 6: Export cipher support
    if test_cipher(host, port, 0x00, 0x03) then
        warnings[#warnings + 1] = "EXPORT cipher supported (FREAK)"
    end

    -- Test 7: 3DES cipher support
    if test_cipher(host, port, 0x00, 0x0A) then
        warnings[#warnings + 1] = "3DES cipher supported (SWEET32 CVE-2016-2183)"
    end

    if #warnings == 0 then
        return nil
    end

    return "SSL/TLS weaknesses: " .. table.concat(warnings, "; ")
end

function test_protocol(host, port, major, minor)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        socket:close()
        return false
    end

    -- ClientHello with specified protocol version
    local random = string.rep(string.char(0x00), 32)
    local hello_body = string.char(major, minor) .. -- requested version
        random ..
        string.char(0x00) .. -- session ID length
        string.char(0x00, 0x02) .. -- cipher suites length
        string.char(0x00, 0x2F) .. -- TLS_RSA_WITH_AES_128_CBC_SHA
        string.char(0x01, 0x00) -- compression (null)

    local handshake = string.char(0x01) ..
        string.char(0x00, math.floor(#hello_body / 256), #hello_body % 256) ..
        hello_body

    local record = string.char(0x16) ..
        string.char(major, minor) ..
        string.char(math.floor(#handshake / 256), #handshake % 256) ..
        handshake

    status, err = socket:send(record)
    if not status then
        socket:close()
        return false
    end

    local ok, data = socket:receive()
    socket:close()

    if ok and #data >= 6 then
        -- ServerHello response means protocol is accepted
        if string.byte(data, 1) == 0x16 and string.byte(data, 6) == 0x02 then
            return true
        end
    end

    return false
end

function test_cipher(host, port, c1, c2)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        socket:close()
        return false
    end

    local random = string.rep(string.char(0x00), 32)
    local hello_body = string.char(0x03, 0x03) .. -- TLS 1.2
        random ..
        string.char(0x00) ..
        string.char(0x00, 0x02) ..
        string.char(c1, c2) ..
        string.char(0x01, 0x00)

    local handshake = string.char(0x01) ..
        string.char(0x00, math.floor(#hello_body / 256), #hello_body % 256) ..
        hello_body

    local record = string.char(0x16) ..
        string.char(0x03, 0x01) ..
        string.char(math.floor(#handshake / 256), #handshake % 256) ..
        handshake

    status, err = socket:send(record)
    if not status then
        socket:close()
        return false
    end

    local ok, data = socket:receive()
    socket:close()

    if ok and #data >= 6 then
        if string.byte(data, 1) == 0x16 and string.byte(data, 6) == 0x02 then
            return true
        end
    end

    return false
end
