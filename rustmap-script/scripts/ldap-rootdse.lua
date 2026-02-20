summary = "Queries LDAP RootDSE for naming contexts and server info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({389, 636}, {"ldap", "ldaps"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- LDAP SearchRequest for RootDSE
    -- MessageID: 1
    -- SearchRequest:
    --   baseObject: "" (empty)
    --   scope: baseObject (0)
    --   derefAliases: neverDerefAliases (0)
    --   sizeLimit: 0
    --   timeLimit: 0
    --   typesOnly: false
    --   filter: (objectClass=*) - present filter
    --   attributes: namingContexts, defaultNamingContext, dnsHostName, serverName

    -- Build the SearchRequest using raw ASN.1/BER encoding
    -- This is a minimal RootDSE query

    -- Filter: (objectClass=*) = present filter for "objectClass"
    local filter = "\x87\x0BobjectClass" -- context tag 7, "objectClass"

    -- Attributes we want
    local attrs = ""
    local attr_names = {"namingContexts", "defaultNamingContext", "dnsHostName", "serverName", "supportedLDAPVersion"}
    for _, name in ipairs(attr_names) do
        attrs = attrs .. "\x04" .. string.char(#name) .. name
    end
    local attr_list = "\x30" .. encode_length(#attrs) .. attrs

    -- SearchRequest body
    local search_body = "\x04\x00" -- baseObject: ""
        .. "\x0A\x01\x00" -- scope: baseObject
        .. "\x0A\x01\x00" -- derefAliases: never
        .. "\x02\x01\x00" -- sizeLimit: 0
        .. "\x02\x01\x00" -- timeLimit: 0
        .. "\x01\x01\x00" -- typesOnly: false
        .. filter
        .. attr_list

    -- SearchRequest tag: APPLICATION 3 (0x63)
    local search_req = "\x63" .. encode_length(#search_body) .. search_body

    -- LDAPMessage: SEQUENCE { messageID, searchRequest }
    local msg_body = "\x02\x01\x01" .. search_req -- messageID: 1
    local ldap_msg = "\x30" .. encode_length(#msg_body) .. msg_body

    status, err = socket:send(ldap_msg)
    if not status then
        socket:close()
        return nil
    end

    -- Read response
    local response = ""
    for i = 1, 3 do
        local ok, data = socket:receive()
        if not ok then break end
        response = response .. data
    end
    socket:close()

    if #response == 0 then
        return nil
    end

    -- Extract readable strings from the LDAP response
    local result = {}

    -- Look for common patterns in the raw response
    for _, attr in ipairs({"namingContexts", "defaultNamingContext", "dnsHostName", "serverName"}) do
        local value = response:match(attr .. "%z*(.-%z)")
        if not value then
            -- Try finding the attribute name followed by readable text
            local start = response:find(attr, 1, true)
            if start then
                -- Look for OctetString values after the attribute name
                local search_from = start + #attr
                local val = extract_ldap_string(response, search_from)
                if val and #val > 0 then
                    result[#result + 1] = attr .. ": " .. val
                end
            end
        end
    end

    if #result == 0 then
        -- At least confirm LDAP is responding
        if #response > 5 and response:byte(1) == 0x30 then
            return "LDAP RootDSE accessible (anonymous bind)"
        end
        return nil
    end

    return table.concat(result, "; ")
end

-- Note: duplicated in ldap-search.lua for script independence
function encode_length(len)
    if len < 128 then
        return string.char(len)
    elseif len < 256 then
        return "\x81" .. string.char(len)
    else
        return "\x82" .. string.char(math.floor(len / 256)) .. string.char(len % 256)
    end
end

function extract_ldap_string(data, start)
    -- Look for BER OctetString (0x04) tag after the given offset.
    -- Limitation: This is a heuristic search, not a full ASN.1/BER parser.
    -- We scan up to 256 bytes from the attribute name to find the value.
    -- Deeply nested or long attributes may be missed.
    local search_end = math.min(start + 256, #data - 2)
    if search_end < start then
        return nil
    end
    for i = start, search_end do
        if data:byte(i) == 0x04 then
            if i + 1 > #data then break end
            local slen = data:byte(i + 1)
            if slen and slen > 0 and slen < 200 and i + 1 + slen <= #data then
                local val = data:sub(i + 2, i + 1 + slen)
                -- Only return printable strings
                if val:match("^[%g%s]+$") then
                    return val
                end
            end
        end
    end
    return nil
end
