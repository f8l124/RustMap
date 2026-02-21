summary = "Enumerates SSL/TLS cipher suites accepted by the server"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({443, 8443, 993, 995, 465, 636, 989, 990}, {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps"}, nil, nil)

-- Cipher suite definitions: {id_byte1, id_byte2, name, grade}
local cipher_suites = {
    -- TLS 1.2 strong ciphers (Grade A)
    {0xC0, 0x2F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "A"},
    {0xC0, 0x30, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "A"},
    {0xC0, 0x2B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "A"},
    {0xC0, 0x2C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "A"},
    {0xCC, 0xA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "A"},
    {0xCC, 0xA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "A"},
    -- TLS 1.2 good ciphers (Grade B)
    {0xC0, 0x13, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "B"},
    {0xC0, 0x14, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "B"},
    {0x00, 0x9C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "B"},
    {0x00, 0x9D, "TLS_RSA_WITH_AES_256_GCM_SHA384", "B"},
    -- TLS 1.2 acceptable (Grade C)
    {0x00, 0x2F, "TLS_RSA_WITH_AES_128_CBC_SHA", "C"},
    {0x00, 0x35, "TLS_RSA_WITH_AES_256_CBC_SHA", "C"},
    {0x00, 0x3C, "TLS_RSA_WITH_AES_128_CBC_SHA256", "C"},
    {0x00, 0x3D, "TLS_RSA_WITH_AES_256_CBC_SHA256", "C"},
    -- Weak ciphers (Grade D)
    {0x00, 0x0A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "D"},
    {0x00, 0x04, "TLS_RSA_WITH_RC4_128_MD5", "F"},
    {0x00, 0x05, "TLS_RSA_WITH_RC4_128_SHA", "F"},
    -- NULL/export (Grade F)
    {0x00, 0x00, "TLS_NULL_WITH_NULL_NULL", "F"},
    {0x00, 0x01, "TLS_RSA_WITH_NULL_MD5", "F"},
    {0x00, 0x02, "TLS_RSA_WITH_NULL_SHA", "F"},
    {0x00, 0x03, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "F"},
}

function action(host, port)
    local accepted = {}
    local best_grade = "F"
    local worst_grade = "A"
    local grade_order = {A = 1, B = 2, C = 3, D = 4, F = 5}

    -- Test each cipher individually
    for _, cipher in ipairs(cipher_suites) do
        local socket = nmap.new_socket()
        socket:set_timeout(3000)

        local status, err = socket:connect(host.ip, port.number)
        if not status then
            socket:close()
            goto next_cipher
        end

        -- Construct TLS 1.2 ClientHello with single cipher
        local client_hello = build_client_hello(host.ip, cipher[1], cipher[2])
        status, err = socket:send(client_hello)
        if not status then
            socket:close()
            goto next_cipher
        end

        local ok, data = socket:receive()
        socket:close()

        if ok and #data >= 6 then
            -- Check for ServerHello (content type 0x16, handshake type 0x02)
            if string.byte(data, 1) == 0x16 and string.byte(data, 6) == 0x02 then
                accepted[#accepted + 1] = cipher[3] .. " (" .. cipher[4] .. ")"
                local g = grade_order[cipher[4]]
                if g < grade_order[best_grade] then best_grade = cipher[4] end
                if g > grade_order[worst_grade] then worst_grade = cipher[4] end
            end
        end

        ::next_cipher::
    end

    if #accepted == 0 then
        return nil
    end

    local result = "Accepted ciphers (" .. #accepted .. "): " .. table.concat(accepted, ", ")
    result = result .. "; Best: " .. best_grade .. ", Worst: " .. worst_grade

    return result
end

function build_client_hello(hostname, c1, c2)
    -- Minimal TLS 1.2 ClientHello
    local random = string.rep(string.char(0x00), 32)

    -- Extensions: SNI
    local sni_host = hostname
    local sni_entry = string.char(0x00) .. -- host name type
        string.char(0x00, #sni_host) ..
        sni_host
    local sni_list = string.char(0x00, #sni_entry + 2) ..
        string.char(0x00, #sni_entry) ..
        sni_entry
    local sni_ext = string.char(0x00, 0x00) .. -- extension type: SNI
        string.char(0x00, #sni_list) ..
        sni_list

    local extensions = sni_ext
    local ext_len = string.char(0x00, #extensions)

    -- ClientHello body
    local hello_body = string.char(0x03, 0x03) .. -- TLS 1.2
        random ..
        string.char(0x00) .. -- session ID length
        string.char(0x00, 0x02) .. -- cipher suites length (1 cipher = 2 bytes)
        string.char(c1, c2) ..
        string.char(0x01, 0x00) .. -- compression methods (null)
        ext_len .. extensions

    -- Handshake header
    local handshake = string.char(0x01) .. -- ClientHello
        string.char(0x00, math.floor(#hello_body / 256), #hello_body % 256) ..
        hello_body

    -- TLS record
    local record = string.char(0x16) .. -- content type: handshake
        string.char(0x03, 0x01) .. -- TLS 1.0 for record layer
        string.char(math.floor(#handshake / 256), #handshake % 256) ..
        handshake

    return record
end
