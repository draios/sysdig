--[[
Copyright (C) 2015 Luca Marturana

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Show top HTTP transactions by: ncalls, time or bytes";
short_description = "Top http connections";
category = "Net";

-- Chisel argument list
args = {
    {
        name = "by",
        description = "Show top HTTP transactions by: ncalls, time or bytes, default is ncalls",
        argtype = "string",
        optional = true
    },
}

require "common"
terminal = require "ansiterminal"

vizinfo =
{
    key_fld = {"method", "url"},
    key_desc = {"method", "url"},
    value_fld = "ncalls",
    value_desc = "ncalls",
    value_units = "none",
    top_number = 30,
    output_format = "normal"
}

by_field = "ncalls"

-- Argument notification callback
function on_set_arg(name, val)
    if name == "by" then
        if val == "time" then
            vizinfo["value_fld"] = "time"
            vizinfo["value_desc"] = "time"
            vizinfo["value_units"] = "time"
        elseif val == "ncalls" then
            vizinfo["value_fld"] = "ncalls"
            vizinfo["value_desc"] = "ncalls"
            vizinfo["value_units"] = "none"
        elseif val == "bytes" then
            vizinfo["value_fld"] = "bytes"
            vizinfo["value_desc"] = "bytes"
            vizinfo["value_units"] = "bytes"
        else
            print("Invalid argument! Valid options: ncalls, bytes, time")
            return false
        end
        by_field = val
        return true
    end
end


-- Initialization callback
function on_init()

    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    chisel.set_filter("evt.is_io = true and evt.buflen.net > 0 and fd.type = ipv4")
    buffer_field = chisel.request_field("evt.buffer")
    fd_field = chisel.request_field("fd.num")
    pid_field = chisel.request_field("proc.pid")
    rawtime_field = chisel.request_field("evt.rawtime")
    buflen_field = chisel.request_field("evt.buflen.net")
    dir_field = chisel.request_field("evt.io_dir")

    if print_container then
        container_field = chisel.request_field("container.name")
        table.insert(vizinfo["key_fld"], 1, "container")
        table.insert(vizinfo["key_desc"], 1, "container")
    end

    sysdig.set_snaplen(1024)
    return true
end

islive = false
grtable = {}
partial_transactions = {}

function parse_request(req_buffer)
    method, url = string.match(req_buffer, "^(%u+) (%g+)")
    if method and url then
        host = string.match(req_buffer, "Host: (%g+)%.%.")
        if host then
            url = host .. url
        end
        return {
            method=method,
            url=url
        }
    end

    return nil
end

function parse_response(resp_buffer)
    resp_code = string.match(resp_buffer, "HTTP/[%g]+ (%d+)")
    if resp_code then
        return tonumber(resp_code)
    else
        return nil
    end
end

function build_grtable_key(transaction)
    request = transaction["request"]
    ret = ""
    if print_container then
        ret = transaction["container"] .. "\001\001"
    end
    ret = ret .. string.format("%s\001\001%s", request["method"], request["url"])
    return ret
end

function on_event()
    buf = evt.field(buffer_field)
    fd = evt.field(fd_field)
    pid = evt.field(pid_field)
    evt_dir = evt.field(dir_field)
    key = string.format("%d\001\001%d", pid, fd)

    timestamp = evt.field(rawtime_field)
    buflen = evt.field(buflen_field)
    transaction = partial_transactions[key]
    if not transaction then
        request = parse_request(buf)
        if request then
            transaction_dir = "<NA>"
            if evt_dir == "read" then
                transaction_dir = "server"
            elseif evt_dir == "write" then
                transaction_dir = "client"
            end
            partial_transactions[key] = {
                ts= timestamp,
                request= request,
                request_len=buflen,
                dir=transaction_dir
            }
            if print_container then
                partial_transactions[key]["container"] = evt.field(container_field)
            end
        end
    else
        response = parse_response(buf)
        if response then
            --print(string.format("%s %s -> %d %d ms %d bytes",
            --    transaction["request"]["method"],
            --    transaction["request"]["url"],
            --    response,
            --    (timestamp - transaction["ts"])/1000000,
            --    transaction["request_len"] + buflen
            --))
            transaction["response_ts"] = timestamp
            transaction["response_len"] = buflen
            transaction["response_code"] = response
            grtable_key = build_grtable_key(transaction)
            if not grtable[grtable_key] then
                grtable[grtable_key] = {}
            end
            table.insert(grtable[grtable_key], transaction)
            partial_transactions[key] = nil
        end
    end
end

-- Final chisel initialization
function on_capture_start()
    islive = sysdig.is_live()
    vizinfo.output_format = sysdig.get_output_format()

    if islive then
        chisel.set_interval_s(1)
        if vizinfo.output_format ~= "json" then
            terminal.clearscreen()
            terminal.hidecursor()
        end
    end

    return true
end

function aggregate_grtable()
    for key, transactions in pairs(grtable) do
        if by_field == "ncalls" then
            grtable[key] = #transactions
        elseif by_field == "bytes" then
            total_bytes = 0
            for _, tr in ipairs(transactions) do
                total_bytes = total_bytes + tr["request_len"] + tr["response_len"]
            end
            grtable[key] = total_bytes
        elseif by_field == "time" then
            total_time = 0
            for _, tr in ipairs(transactions) do
                total_time = total_time + tr["response_ts"] - tr["ts"]
            end
            grtable[key] = total_time / #transactions
        end
    end
end

function on_interval(ts_s, ts_ns, delta)
    if vizinfo.output_format ~= "json" then
        terminal.clearscreen()
        terminal.moveto(0, 0)
    end

    aggregate_grtable()
    print_sorted_table(grtable, ts_s, 0, delta, vizinfo)

    -- Clear the table
    grtable = {}
    return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
    if islive and vizinfo.output_format ~= "json" then
        terminal.clearscreen()
        terminal.moveto(0 ,0)
        terminal.showcursor()
        return true
    end

    aggregate_grtable()
    print_sorted_table(grtable, ts_s, 0, delta, vizinfo)

    return true
end