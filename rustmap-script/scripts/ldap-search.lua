summary = "Tests anonymous LDAP bind and base search access"
categories = {"safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({389, 636}, {"ldap", "ldaps"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Step 1: Anonymous Simple Bind
    -- BindRequest: version=3, name="", authentication=simple("")
    local bind_body = "\x02\x01\x03" -- version: 3
        .. "\x04\x00"               -- name: "" (empty)
        .. "\x80\x00"               -- authentication: simple, "" (empty)

    local bind_req = "\x60" .. string.char(#bind_body) .. bind_body
    local msg_body = "\x02\x01\x01" .. bind_req
    local ldap_msg = "\x30" .. string.char(#msg_body) .. msg_body

    status, err = socket:send(ldap_msg)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()
    if not ok or not data or #data < 10 then
        socket:close()
        return nil
    end

    -- Check BindResponse result code
    -- Look for the resultCode integer in the response
    local bind_success = false
    -- Simple check: look for resultCode 0 (success) in the BindResponse
    -- BindResponse tag is 0x61 (APPLICATION 1)
    if data:find("\x61", 1, true) then
        -- Find the resultCode (ENUMERATED, tag 0x0A, should be 0 for success)
        for i = 1, #data - 2 do
            if data:byte(i) == 0x0A and data:byte(i + 1) == 0x01 then
                if data:byte(i + 2) == 0x00 then
                    bind_success = true
                end
                break
            end
        end
    end

    if not bind_success then
        socket:close()
        return "Anonymous bind: rejected"
    end

    -- Step 2: Base search on "" to confirm access
    local filter = "\x87\x0BobjectClass"
    local attrs = "\x04\x10namingContexts"
    local attr_list = "\x30" .. string.char(#attrs) .. attrs

    local search_body = "\x04\x00" -- baseObject: ""
        .. "\x0A\x01\x00"          -- scope: base
        .. "\x0A\x01\x00"          -- derefAliases: never
        .. "\x02\x01\x00"          -- sizeLimit: 0
        .. "\x02\x01\x05"          -- timeLimit: 5
        .. "\x01\x01\x00"          -- typesOnly: false
        .. filter
        .. attr_list

    local search_req = "\x63" .. encode_length(#search_body) .. search_body
    local msg_body2 = "\x02\x01\x02" .. search_req
    local ldap_msg2 = "\x30" .. encode_length(#msg_body2) .. msg_body2

    status, err = socket:send(ldap_msg2)
    if not status then
        socket:close()
        return "Anonymous bind: success; search: failed to send"
    end

    local response = ""
    for i = 1, 3 do
        ok, data = socket:receive()
        if not ok then break end
        response = response .. data
    end
    socket:close()

    if #response > 0 and response:byte(1) == 0x30 then
        return "Anonymous bind: success; base search: accessible"
    else
        return "Anonymous bind: success; base search: no results"
    end
end

-- Note: duplicated in ldap-rootdse.lua for script independence
function encode_length(len)
    if len < 128 then
        return string.char(len)
    elseif len < 256 then
        return "\x81" .. string.char(len)
    else
        return "\x82" .. string.char(math.floor(len / 256)) .. string.char(len % 256)
    end
end
