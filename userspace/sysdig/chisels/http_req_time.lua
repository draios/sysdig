-- Chisel description
description = "Draw HTTP request time spectrogram"
short_description = "HTTP request time"
category = "Network"

-- Chisel argument list
args = {
    {
        name = "url_filter",
        description = "Regex filter",
        argtype = "string",
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
require "http"
terminal = require "ansiterminal"
terminal.enable_color(true)

refresh_time = 1000000000
refresh_per_sec = 1000000000 / refresh_time

count = 0
frequencies = {}
sliding_window = {}
sliding_window_pos = 0
sliding_window_size = 0
sliding_window_max = 10240

colpalette = {22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1}
url_filter = nil

-- Argument notification callback
function on_set_arg(name, val)
    if name == "url_filter" then
        url_filter = val
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
    is_tty = sysdig.is_tty()

    if not is_tty then
        print("This chisel only works on ANSI terminals. Aborting.")
        return false
    end

    tinfo = sysdig.get_terminal_info()
    w = tinfo.width
    h = tinfo.height

    terminal.hidecursor()

    http_init()

    print("\n")

    return true
end

-- Final chisel initialization
function on_capture_start()
    chisel.set_interval_ns(refresh_time)
    return true
end

function update_frequency(ns)
    local llatency = math.log10(ns)

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

function on_transaction(transaction)
    if url_filter == nil or string.match(transaction["request"]["url"], url_filter) then
        local val = transaction["response"]["ts"] - transaction["request"]["ts"]

        if sliding_window_max > sliding_window_size then
            sliding_window_size = sliding_window_size + 1
        end
        sliding_window[sliding_window_pos + 1] = val
        sliding_window_pos = (sliding_window_pos + 1) % sliding_window_max
        update_frequency(val)
    end
end

-- Event parsing callback
function on_event()
    run_http_parser(evt, on_transaction)
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

    local sorted_window = sliding_window
    table.sort(sorted_window)
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
