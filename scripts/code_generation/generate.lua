-- Generate event defintions for sysdig
-- (c) 2014 Konstantin Tokarev

require "strict"

-- Makes table immutable and forbids indexing undeclared keys
-- Inspired by strict.lua
local function protect_table(table, tablename)
    local mt = {}
    mt.tn = tablename
    mt.__newindex = function(t, n, v)
        local varname = mt.tn .. '.' .. n
        error("cannot assign variable '" .. varname .. '" - table is protected', 2)
    end
    mt.__index = function(t, n)
        local value = rawget(t, n)
        if not value then
            local varname = mt.tn .. '.' .. n
            error("variable '" .. varname .."' is not defined", 2)
        end
        return value
    end
    setmetatable(table, mt)
end

local function generated_file_header(input_files)
    return '/* This file was automatically generated from '
        .. table.concat(input_files, ', ')
        .. '\n'
        .. '        All changes will be lost */'
        .. '\n\n'
end

-- Opens file for write
local function openw(dir, file, header)
    local f = assert(io.open(dir .. "/" .. file, "w"))
    if header then
        assert(f:write(header))
    end
    return f
end

-- Parse command line args
local function parse_args(args)
    local curopt
    local input_files = {}
    local options = {}

    for i, arg in ipairs(args) do
        if arg:find("^-") then
            assert(i < #args, arg .. " requires argument")
            curopt = arg
        else
            if curopt then
                options[curopt] = arg
            else
                input_files[#input_files + 1] = arg
            end
            curopt = nil
        end
    end
    return input_files, options
end

local function parse_event_counter(file)
    local f = io.open(file, 'r')
    local lineNo = 1
    for line in f:lines() do
        if line:find('PPM_FIRST_GENERATED_EVENT') then
            local _, _, v = line:find('^%s*PPM_FIRST_GENERATED_EVENT%s*=%s(%d*)')
            if v then
                assert(line:find(',%s*$'), "comma ',' is missing after PPM_FIRST_GENERATED_EVENT value at "
                       .. file .. ":" .. lineNo)
                return v
            end
            break
        end
        lineNo = lineNo + 1
    end
    error("valid PPM_FIRST_GENERATED_EVENT value not found")
    return 158
end


-----------------------------------
-- Serialization of data structures
-----------------------------------

local function quoted(str)
    return '"' .. (str or '') .. '"'
end

local function c_array(array, sep)
    sep = sep or ' '
    return '{ ' .. table.concat(array, ',' .. sep) .. ' }'
end

local function serialize_event_params(event_params)
    local res = {}
    for _, p in ipairs(event_params) do
        -- Insert defaults
        if not p.type then error("type is missing") end
        if not p.fmt  then error("fmt is missing") end
        res[#res + 1] = c_array { quoted(p.name), p.type, p.fmt, p.flags }
    end
    return res
end

local function serialize_flags(flags)
    if type(flags) ~= "table" then
        return tostring(flags)
    elseif #flags == 1 then
        return tostring(flags[1])
    else
        return '(enum ppm_event_flags)(' .. table.concat(flags, ' | ') .. ')'
    end
end

local function serialize_autofill(params)
    local paramtype = "APT_REG"
    if type(params[1]) == "string" then
        -- Assert on unknown type?
        if params[1]:find("^APT_") then
            paramtype = table.remove(params, 1)
        end
    end
    local nums = {}
    for _, v in ipairs(params) do
        nums[#nums + 1] = '{' .. v .. '}'
    end
    return table.concat({"PPM_AUTOFILL", #nums, paramtype, c_array(nums)}, ', ')
end

-----------------------------------
-- Code writers
-----------------------------------

local input_files, options = parse_args(arg)
local output_dir = assert(options["-o"], "-o option (output directory) is missing")
local event_counter_file = assert(options["-p"], "-p option (ppm_events_public.h path) is missing")
local event_counter = parse_event_counter(event_counter_file)
local file_header

if options["--header"] then
    file_header = generated_file_header(input_files)
end

local event_type = openw(output_dir, "event_type.inc", file_header)
local event_info = openw(output_dir, "event_info.inc", file_header)
local syscall_table = openw(output_dir, "syscall_table.inc", file_header)
local flags_h = openw(output_dir, "flags.h", file_header)
local flags_inc = openw(output_dir, "flags.inc", file_header)
local fillers = openw(output_dir, "ppm_events.inc", file_header)

local function write_event_type(id)
    event_type:write(id, " = ", event_counter, ",\n")
end

local function finalize_event_type()
    event_type:write("PPM_EVENT_MAX = ", event_counter, "\n")
end

local function write_event_info(id, props, params)
    local comment = '/* ' .. id .. ' */'
    local param_array = serialize_event_params(params)
    if not props.flags then
        props.flags = { "EF_NONE" }
    end
    local info = {
        quoted(props.name),
        props.category,
        serialize_flags(props.flags),
        #param_array,
        c_array(param_array)
    }

    event_info:write(comment, c_array(info, '\n\t'), ',\n')
end

local function write_event(id, props, params)
    write_event_type(id)
    write_event_info(id, props, params)
    event_counter = event_counter + 1
end

local function write_filler(id, filler)
    fillers:write('[', id, '] = {', filler, '},\n')
end

local function write_syscall_table(props, evt_e, evt_x)
    local NR_syscall = '__NR_' .. props.name
    local uf_flags = props.never_drop and 'UF_USED | UF_NEVER_DROP' or 'UF_USED'
    local value = c_array{uf_flags, evt_e, evt_x}
    syscall_table:write(
        '#ifdef ', NR_syscall, '\n',
            '\t[', NR_syscall, ' - SYSCALL_TABLE_ID0] =\t\t', value, ',\n',
        '#endif\n'
    )
end

local function required_field(t, field)
    assert(t[field], "required field '" .. field .. "' is missign")
end

local function validate_event_entry(props)
    required_field(props, "name")
    required_field(props, "kind")
    required_field(props, "category")
    required_field(props, "enter_params")
    required_field(props, "exit_params")
end

local function write_events(table)
    for _, props in ipairs(table) do
        validate_event_entry(props)

        local id_prefix
        if props.kind == "syscall" then
            id_prefix = "PPME_SYSCALL_"
        elseif props.kind == "socketcall" then
            id_prefix = "PPME_SOCKET_"
        elseif props.kind == "none" then
            id_prefix = "PPME_"
        else
            error("invalid event kind = " .. props.kind)
        end

        local id_suffix = ""
        if props.version then
            id_suffix = "_" .. props.version
        end

        local evt_id = id_prefix .. props.name:upper() .. id_suffix
        local enter_evt_id = evt_id .. "_E"
        local exit_evt_id = evt_id .. "_X"

        write_event(enter_evt_id, props, props.enter_params)
        write_event(exit_evt_id, props, props.exit_params)

        if props.fillers then
            if props.fillers.enter then
                write_filler(enter_evt_id, props.fillers.enter)
            end
            if props.fillers.exit then
                write_filler(exit_evt_id, props.fillers.exit)
            end
        end

        write_syscall_table(props, enter_evt_id, exit_evt_id)
    end
    finalize_event_type()
end

local function write_flags_h(name, flags)
    flags_h:write('/* ', name, '*/\n')

    if flags[0] then
        flags_h:write('#define PPM_', flags[0], '\t\t0\n')
    end
    for i, flag in ipairs(flags) do
        flags_h:write('#define PPM_', flag, '\t\t(1 << ', i-1, ')\n')
    end

    flags_h:write('\nextern const struct ppm_name_value ',
                  name, '[];\n\n')
end

local function write_flags_inc(name, flags)
    flags_inc:write('const struct ppm_name_value ', name, '[] = {\n')
    if flags[0] then
        flags_inc:write('\t{ "', flags[0], '", PPM_', flags[0], ' },\n')
    end
    for _, flag in ipairs(flags) do
        flags_inc:write('\t{ "', flag, '", PPM_', flag, ' },\n')
    end
    flags_inc:write('\t{ }\n', '};\n\n')
end

local function write_flags(table)
    for k, v in pairs(table) do
        local array_name = k .. "_flags" -- e.g. "file_flags"
        write_flags_h(array_name, v)
        write_flags_inc(array_name, v)
        table[k] = array_name
    end
end


-----------------------------------
-- API generators
-----------------------------------

-- API function with 1 paramter (name), uses predefined type and fmt, no flags
local function api_name(_type, _fmt)
    assert(_type and _fmt, "Invalid api declaration")
    return function(pname)
        return { name = pname, type = _type, fmt = _fmt }
    end
end

-- API function with 2 parameters (name, fmt), uses predefined type,
-- fmt is optional (predefined used if left unspecifed)
-- no flags
local function api_name_fmt(_type, _fmt)
    assert(_type, "Invalid api declaration")
    return function(pname, pfmt)
        return { name = pname, type = _type, fmt = pfmt or _fmt }
    end
end

-- API function with 2 parameters (name, flags), uses predefined type and fmt
local function api_name_flags(_type, _fmt)
    assert(_type and _fmt, "Invalid api declaration")
    return function(pname, pflags)
        return { name = pname, type = _type, fmt = _fmt, flags = pflags }
    end
end

---------------------------------------
-- Global declarations for events.lua
---------------------------------------

flags = function(t)
    write_flags(t)
    protect_table(t, "flags")
    _G.flags = t -- Use flags.xxx in code below
end

events = function(t)
    write_events(t)
    _G.events = nil -- Only one events{} block is allowed
end

AUTOFILL = function(...)
    return serialize_autofill({...})
end

REG  = "APT_REG"
SOCK = "APT_SOCK"

DEFAULT = "AF_ID_USEDEFAULT, 0"
RETVAL = "AF_ID_RETVAL"

DEC = "PF_DEC"
HEX = "PF_HEX"

INT8    = api_name_fmt("PT_INT8", "PF_DEC")
INT16   = api_name_fmt("PT_INT16", "PF_DEC")
INT32   = api_name_fmt("PT_INT32", "PF_DEC")
INT64   = api_name_fmt("PT_INT64", "PF_DEC")
UINT8   = api_name_fmt("PT_UINT8", "PF_DEC")
UINT16  = api_name_fmt("PT_UINT16", "PF_DEC")
UINT32  = api_name_fmt("PT_UINT32", "PF_DEC")
UINT64  = api_name_fmt("PT_UINT64", "PF_DEC")

ERRNO   = api_name("PT_ERRNO", "PF_DEC")
FD      = api_name("PT_FD",    "PF_DEC")
PID     = api_name("PT_PID",   "PF_DEC")

FLAGS8  = api_name_flags("PT_FLAGS8",  "PF_DEC")
FLAGS16 = api_name_flags("PT_FLAGS16", "PF_HEX")
FLAGS32 = api_name_flags("PT_FLAGS32", "PF_HEX")

-----------------------------------
-- Do it!
-----------------------------------

for _, file in ipairs(input_files) do
    assert(loadfile(file))()
end
