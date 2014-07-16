require "strict"

local scratchdir = '__tmp'
local inputfile = scratchdir .. '/input.lua'
local event_type_file = scratchdir .. "/event_type.h"

local function prepare_scratch_dir()
    -- FIXME: Windows support?
    os.execute("rm -rf " .. scratchdir .. " && mkdir " .. scratchdir)
end

local function write_file(name, str)
    local f = io.open(name, 'w')
    f:write(str)
    f:close()
end

local function exec(...)
    return os.execute(table.concat({...}, ' '))
end

local function do_generate()
    -- Run generate.lua in separate Lua state
    local res = exec(arg[-1], "generate.lua", "-o", "__tmp", "-p", event_type_file, inputfile)
    assert(res == 0, "generate.lua failed")
end

local function fix_spaces(str)
    -- Trim
    str = str:gsub("^%s+", "")
    str = str:gsub("%s+$", "")
    -- Replace inner whitespaces with single space character
    str = str:gsub("%s+", " ")
    return str
end

local function check_file(fname, pattern)
    local f = assert(io.open('__tmp/' .. fname))
    local content = fix_spaces(f:read("*a"))
    pattern = fix_spaces(pattern)
    f:close()

    if pattern:find('%^') then
        assert(content:find(pattern),
            "test failed:\n\t" .. fname .. "\nexpected: '" .. pattern .. "'\nactual:   '" .. content .. "'")
    else
        assert(content == pattern,
            "test failed:\n\t" .. fname .. "\nexpected: '" .. pattern .. "'\nactual:   '" .. content .. "'")
    end
end

local test_number = 1

function test(t)
    prepare_scratch_dir()
    write_file(event_type_file, t.event_type or [[
        enum ppm_event_type {
            PPME_CLONE_16_E = 156,
            PPME_CLONE_16_X = 157,
            PPM_FIRST_GENERATED_EVENT = 158,
            #include "event_type.inc"
        }
    ]])

    write_file(inputfile, t.input)
    do_generate()
    for k, v in pairs(t.output) do
        check_file(k, v)
    end
    print("Test #" .. test_number .. " - OK")
    test_number = test_number + 1
end

assert(loadfile("tests.lua"))()
