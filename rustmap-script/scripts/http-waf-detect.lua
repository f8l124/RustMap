summary = "Detects Web Application Firewalls via response analysis"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({80, 443, 8080, 8443}, {"http", "https"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Send a request with common attack patterns to trigger WAF
    local request = "GET /?id=1%20AND%201=1%20UNION%20SELECT%201,2,3 HTTP/1.1\r\n" ..
        "Host: " .. host.ip .. "\r\n" ..
        "User-Agent: rustmap\r\n" ..
        "Connection: close\r\n\r\n"
    status, err = socket:send(request)
    if not status then
        socket:close()
        return nil
    end

    local max_response_size = 1048576
    local response = ""
    while true do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
        if #response > max_response_size then break end
    end
    socket:close()

    if #response == 0 then
        return nil
    end

    local headers = response:match("^(.-)\r\n\r\n") or ""
    local lower_headers = headers:lower()
    local body = response:match("\r\n\r\n(.+)") or ""
    local lower_body = body:lower()

    local waf_signatures = {}

    -- Cloudflare
    if lower_headers:match("cf%-ray:") or lower_headers:match("server:%s*cloudflare") then
        waf_signatures[#waf_signatures + 1] = "Cloudflare"
    end

    -- AWS WAF / CloudFront
    if lower_headers:match("x%-amzn%-requestid:") or lower_headers:match("x%-amz%-cf%-id:") then
        waf_signatures[#waf_signatures + 1] = "AWS WAF/CloudFront"
    end

    -- Akamai
    if lower_headers:match("x%-akamai%-") or lower_headers:match("akamaighost") then
        waf_signatures[#waf_signatures + 1] = "Akamai"
    end

    -- Sucuri
    if lower_headers:match("x%-sucuri%-id:") or lower_headers:match("sucuri") then
        waf_signatures[#waf_signatures + 1] = "Sucuri"
    end

    -- ModSecurity
    if lower_headers:match("mod_security") or lower_body:match("mod_security") then
        waf_signatures[#waf_signatures + 1] = "ModSecurity"
    end

    -- Imperva / Incapsula
    if lower_headers:match("x%-iinfo:") or lower_headers:match("incap_ses") then
        waf_signatures[#waf_signatures + 1] = "Imperva/Incapsula"
    end

    -- F5 BIG-IP ASM
    if lower_headers:match("x%-waf%-status:") or lower_headers:match("bigipserver") then
        waf_signatures[#waf_signatures + 1] = "F5 BIG-IP"
    end

    -- Barracuda
    if lower_headers:match("barra_counter_session") then
        waf_signatures[#waf_signatures + 1] = "Barracuda"
    end

    -- DenyAll
    if lower_headers:match("sessioncookie=") and lower_headers:match("denyall") then
        waf_signatures[#waf_signatures + 1] = "DenyAll"
    end

    -- Fortinet FortiWeb
    if lower_headers:match("fortiwafsid") then
        waf_signatures[#waf_signatures + 1] = "FortiWeb"
    end

    -- Generic WAF indicators
    local status_code = response:match("^HTTP/%d[%.%d]* (%d+)")
    if status_code == "403" or status_code == "406" or status_code == "429" then
        if lower_body:match("blocked") or lower_body:match("firewall") or lower_body:match("access denied") then
            if #waf_signatures == 0 then
                waf_signatures[#waf_signatures + 1] = "Unknown WAF (blocked response)"
            end
        end
    end

    if #waf_signatures == 0 then
        return nil
    end

    return "WAF detected: " .. table.concat(waf_signatures, ", ")
end
