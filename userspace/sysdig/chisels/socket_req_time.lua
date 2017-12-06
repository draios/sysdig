-- Chisel description
description = "Draw spectrogram between request and responce, to choosen ip or/and port. \n" .. 
    "Depending on first parameter 'in/out' it calculates time between respectively 'first read - last write' or 'first write - last read'"
short_description = "Sockets request/responce time"
category = "Network"

-- Chisel argument list
args = {
    {
        name = "direction",
        description = "in/out",
        argtype = "string"
    },
    {
        name = "ip",
        description = "Target IP",
        argtype = "string",
        optional = true
    },
    {
        name = "port",
        description = "Target port",
        argtype = "int",
        optional = true
    },
    {
        name = "refresh_time",
        description = "Chart refresh time in milliseconds",
        argtype = "int",
        optional = true
    }
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

write_etypes = {}
write_etypes["sendto"] = true
write_etypes["writev"] = true
write_etypes["write"] = true
write_etypes["pwrite"] = true

read_etypes = {}
read_etypes["recvfrom"] = true
read_etypes["readv"] = true
read_etypes["read"] = true
read_etypes["pread"] = true

refresh_time = 1000000000
refresh_per_sec = 1000000000 / refresh_time

time_map = {}

count = 0
frequencies = {}

sliding_window = {}
sliding_window_pos = 0
sliding_window_size = 0
sliding_window_max = 10240

function dump(o)
    if type(o) == "table" then
        local s = "{ "
        for k, v in pairs(o) do
            if type(k) ~= "number" then
                k = '"' .. k .. '"'
            end
            s = s .. "[" .. k .. "] = " .. dump(v) .. ","
        end
        return s .. "} "
    else
        return tostring(o)
    end
end

function shallowcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == "table" then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

colpalette = {22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1}
ip = ""
port = 0

-- Argument notification callback
function on_set_arg(name, val)
    if name == "direction" then
        direction = val
        return true
    elseif name == "ip" then
        ip = val
        return true
    elseif name == "port" then
        port = val
        return true
    elseif name == "refresh_time" then
        refresh_time = parse_numeric_input(val, name) * 1000000
        refresh_per_sec = 1000000000 / refresh_time
        return true
    end
    return false
end

-- Initialization callback
function on_init()
    if (port == nil or port == 0) and (ip == nil or ip == "") then
        print("IP or port, or both must be selected")
        return false
    end

    is_tty = sysdig.is_tty()

    if not is_tty then
        print("This chisel only works on ANSI terminals. Aborting.")
        return false
    end

    tinfo = sysdig.get_terminal_info()
    w = tinfo.width
    h = tinfo.height

    terminal.hidecursor()

    -- Request the fileds that we need
    field_pid = chisel.request_field("proc.pid")
    field_fdnum = chisel.request_field("fd.num")
    field_etype = chisel.request_field("evt.type")
    field_etime = chisel.request_field("evt.rawtime")
    field_edir = chisel.request_field("evt.dir")

    local filter = "evt.is_io=true and fd.type=ipv4"

    if port ~= nil and port ~= 0 then
        filter = filter .. " and fd.port=" .. port
    end

    if ip ~= nil and ip ~= "" then
        filter = filter .. " and fd.ip=" .. ip
    end

    print("\n")

    chisel.set_filter(filter)
    return true
end

-- Final chisel initialization
function on_capture_start()
    chisel.set_interval_ns(refresh_time)
    return true
end

function update_frequency(pid, fdnum)
    if time_map[pid] ~= nil and time_map[pid][fdnum] ~= nil then
        local raw_latency = time_map[pid][fdnum].stop - time_map[pid][fdnum].start

        if sliding_window_max > sliding_window_size then
            sliding_window_size = sliding_window_size + 1
        end
        sliding_window[sliding_window_pos + 1] = raw_latency
        sliding_window_pos = (sliding_window_pos + 1) % sliding_window_max

        local llatency = math.log10(raw_latency)

        if (llatency > 11) then
            llatency = 11
        end

        local norm_llatency = math.floor(llatency * w / 11) + 1

        if frequencies[norm_llatency] == nil then
            frequencies[norm_llatency] = 1
        else
            frequencies[norm_llatency] = frequencies[norm_llatency] + 1
        end

        count = count + 1
    end
end

-- Event parsing callback
function on_event()
    local pid = evt.field(field_pid)
    local fdnum = evt.field(field_fdnum)
    local etype = evt.field(field_etype)
    local etime = evt.field(field_etime)
    local edir = evt.field(field_edir)

    if
        (direction == "out" and write_etypes[etype] == true and edir == ">") or
            (direction == "in" and read_etypes[etype] == true and edir == ">")
     then
        if time_map[pid] == nil then
            time_map[pid] = {}
        end

        if time_map[pid][fdnum] ~= nil then
            if time_map[pid][fdnum].direction == "<" then
                update_frequency(pid, fdnum)

                time_map[pid][fdnum].direction = ">"
                time_map[pid][fdnum].start = etime
                time_map[pid][fdnum].stop = etime
            end
        else
            time_map[pid][fdnum] = {
                start = etime,
                stop = etime,
                direction = ">"
            }
        end
    elseif
        (direction == "out" and read_etypes[etype] == true and edir == "<") or
            (direction == "in" and write_etypes[etype] == true and edir == "<")
     then
        if time_map[pid] ~= nil and time_map[pid][fdnum] ~= nil then
            time_map[pid][fdnum].direction = "<"
            time_map[pid][fdnum].stop = etime
        end
    end

    return true
end

function mkcol(n)
    local col = math.floor(math.log10(n * refresh_per_sec + 1) / math.log10(1.6))

    if col < 1 then
        col = 1
    end

    if col > #colpalette then
        col = #colpalette
    end

    return colpalette[col]
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)
    close_old(ts_s, ts_ns, delta)

    terminal.moveup(2)

    for x = 1, w do
        local fr = frequencies[x]
        if fr == nil or fr == 0 then
            terminal.setbgcol(0)
        else
            terminal.setbgcol(mkcol(fr))
        end

        io.write(" ")
    end

    io.write(terminal.reset .. "\n")

    local sorted_window = shallowcopy(sliding_window)
    table.sort(sorted_window)
    --io.write(dump(sorted_window) .. "\n")
    local p50 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.5)])
    local p75 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.75)])
    local p90 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.90)])
    local p95 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.95)])
    local p99 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.99)])
    local p999 = format_time_interval(sorted_window[math.floor(sliding_window_size * 0.999)])
    local min_lat = format_time_interval(sorted_window[1])
    local maxIdx = 1
    if sliding_window_size > 0 then
        maxIdx = sliding_window_size
    end
    local max_lat = format_time_interval(sorted_window[maxIdx])

    terminal.clearline()
    io.write(
        string.format(
            "RPS = %d\tp50 = %s\tp75 = %s\tp90 = %s\tp95 = %s\tp99 = %s\tp999 = %s\tmin = %s\tmax = %s\n",
            count * refresh_per_sec,
            p50,
            p75,
            p90,
            p95,
            p99,
            p999,
            min_lat,
            max_lat
        )
    )

    local x = 0
    while true do
        if x >= w then
            break
        end

        local curtime = math.floor(x * 11 / w)
        local prevtime = math.floor((x - 1) * 11 / w)

        if curtime ~= prevtime then
            io.write("|")
            local tstr = format_time_interval(math.pow(10, curtime))
            io.write(tstr)
            x = x + #tstr + 1
        else
            io.write(" ")
            x = x + 1
        end
    end

    io.write("\n")

    frequencies = {}
    count = 0

    return true
end

function close_old(ts_s, ts_ns, delta)
    for pid, fdescs in pairs(time_map) do
        for fdnum, data in pairs(fdescs) do
            if data.stop < (ts_s * 1000000000 + ts_ns) and data.stop > data.start then
                update_frequency(pid, fdnum)
                time_map[pid][fdnum] = nil
            end
        end
    end
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
    if is_tty then
        -- Include the last sample
        on_interval(ts_s, ts_ns, 0)

        -- reset the terminal
        print(terminal.reset)
        terminal.showcursor()
    end
    return true
end
