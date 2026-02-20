summary = "Queries MongoDB isMaster/hello command for version and replication info"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}

portrule = shortport.port_or_service({27017}, {"mongodb"}, nil, nil)

function action(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end

    -- Try OP_MSG first (MongoDB 3.6+).
    -- Note: OP_QUERY (opcode 2004) was removed in MongoDB 6.0+.
    -- We use OP_MSG (opcode 2013) as the primary method, with OP_QUERY as fallback
    -- for servers older than MongoDB 3.6 that don't support OP_MSG.

    -- BSON document: {"isMaster": 1, "$db": "admin"}
    -- Build the BSON manually:
    -- \x01 = double type, "isMaster\0", double 1.0
    -- \x02 = string type, "$db\0", string "admin\0"
    local bson_inner = ""
        .. "\x01" .. "isMaster\x00"
        .. "\x00\x00\x00\x00\x00\x00\xF0\x3F" -- double 1.0
        .. "\x02" .. "$db\x00"
        .. "\x06\x00\x00\x00" -- string length including null (6)
        .. "admin\x00"
        .. "\x00" -- document terminator

    local bson_len = #bson_inner + 4 -- 4 bytes for length prefix
    local bson_doc = string.char(bson_len % 256, math.floor(bson_len / 256) % 256, 0, 0)
        .. bson_inner

    -- OP_MSG body: flagBits(4) + section kind 0(1) + bson document
    local msg_body = "\x00\x00\x00\x00" -- flagBits
        .. "\x00" -- section kind: body
        .. bson_doc

    -- Message header: length(4) + requestID(4) + responseTo(4) + opCode(4)
    local msg_len = 16 + #msg_body
    local header = string.char(msg_len % 256, math.floor(msg_len / 256) % 256, 0, 0)
        .. "\x01\x00\x00\x00" -- requestID
        .. "\x00\x00\x00\x00" -- responseTo
        .. "\xDD\x07\x00\x00" -- opCode: OP_MSG (2013)

    status, err = socket:send(header .. msg_body)
    if not status then
        socket:close()
        return nil
    end

    local ok, data = socket:receive()

    if not ok or not data or #data < 20 then
        -- OP_MSG failed; try OP_QUERY fallback for MongoDB < 3.6
        -- Note: OP_QUERY (opcode 2004) targets MongoDB < 6.0 only
        socket:close()
        socket = nmap.new_socket()
        socket:set_timeout(5000)
        status, err = socket:connect(host.ip, port.number)
        if not status then return nil end

        -- Build OP_QUERY for isMaster on admin.$cmd
        local query_ns = "admin.$cmd\x00"
        -- BSON: {"isMaster": 1}
        local query_bson_inner = "\x01" .. "isMaster\x00"
            .. "\x00\x00\x00\x00\x00\x00\xF0\x3F" -- double 1.0
            .. "\x00" -- document terminator
        local query_bson_len = #query_bson_inner + 4
        local query_bson = string.char(query_bson_len % 256, math.floor(query_bson_len / 256) % 256, 0, 0)
            .. query_bson_inner

        local query_body = "\x00\x00\x00\x00" -- flags
            .. query_ns
            .. "\x00\x00\x00\x00" -- numberToSkip
            .. "\x01\x00\x00\x00" -- numberToReturn (1)
            .. query_bson

        local query_msg_len = 16 + #query_body
        local query_header = string.char(query_msg_len % 256, math.floor(query_msg_len / 256) % 256, 0, 0)
            .. "\x02\x00\x00\x00" -- requestID
            .. "\x00\x00\x00\x00" -- responseTo
            .. "\xD4\x07\x00\x00" -- opCode: OP_QUERY (2004)

        status, err = socket:send(query_header .. query_body)
        if not status then
            socket:close()
            return nil
        end

        ok, data = socket:receive()
        socket:close()

        if not ok or not data or #data < 20 then
            return nil
        end
    else
        socket:close()
    end

    -- Extract a BSON string field value: type 0x02, then "name\0", then int32 len, then string\0
    -- Returns the string value or nil.
    local function bson_string(field_name)
        local search = "\x02" .. field_name .. "\x00"
        local pos = data:find(search, 1, true)
        if not pos then return nil end
        local val_start = pos + #search
        if val_start + 3 > #data then return nil end
        local slen = data:byte(val_start) + data:byte(val_start + 1) * 256
            + data:byte(val_start + 2) * 65536 + data:byte(val_start + 3) * 16777216
        if slen < 1 or slen > 256 then return nil end
        local str_start = val_start + 4
        if str_start + slen - 2 > #data then return nil end
        return data:sub(str_start, str_start + slen - 2) -- exclude trailing null
    end

    local result = {}

    -- Look for "version" field (BSON string type \x02)
    local version = bson_string("version")
    if version and version:match("^[%d%.]+$") then
        result[#result + 1] = "Version: " .. version
    end

    -- Look for "ismaster" boolean field
    -- BSON boolean is type \x08, then field name\0, then \x01 (true) or \x00 (false)
    -- Important: we check the actual boolean value, not just field presence
    local ismaster_search = "\x08" .. "ismaster\x00"
    local ismaster_pos = data:find(ismaster_search, 1, true)
    if ismaster_pos then
        local bool_offset = ismaster_pos + #ismaster_search
        if bool_offset <= #data then
            local bool_byte = data:byte(bool_offset)
            if bool_byte == 1 then
                result[#result + 1] = "isMaster: true"
            elseif bool_byte == 0 then
                result[#result + 1] = "isMaster: false"
            end
        end
    end

    -- Look for "setName" (replica set) — BSON string field
    local setname = bson_string("setName")
    if setname and #setname > 0 then
        result[#result + 1] = "ReplicaSet: " .. setname
    end

    -- Look for "maxBsonObjectSize" which confirms it's MongoDB
    if data:find("maxBsonObjectSize", 1, true) then
        result[#result + 1] = "MongoDB detected"
    end

    if #result == 0 then
        return nil
    end

    return table.concat(result, "; ")
end
