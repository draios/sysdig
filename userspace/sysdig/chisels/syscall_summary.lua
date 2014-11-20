--[[
Copyright (C) 2014 Jonathan Cua.

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

-- The number of items to show
TOP_NUMBER = 10

-- Chisel description
description = "Show summary of the " .. TOP_NUMBER .. " highest system calls counts. You can use filters to restrict this to a specific process, thread or file."
short_description = "Summary of counts of system calls"
category = "Performance"

-- Chisel argument list
args = {}

record_for = {}
terminal = require "ansiterminal"

-- Argument notification callback
function on_set_arg(name, val)
    return false
end

-- Initialization callback
function on_init()
    fevtype = chisel.request_field("evt.type")
    fcount = chisel.request_field("evt.count")
    ferror = chisel.request_field("evt.failed")
    flatency = chisel.request_field("evt.latency")

    chisel.set_filter("evt.dir=<")
    return true
end

-- Event parsing callback
function on_event()
    evtype = evt.field(fevtype)
    count = evt.field(fcount)
    error = evt.field(ferror)
    latency = evt.field(flatency)

    if evtype == "switch" then
        return true
    end

    if record_for[evtype] == nil then
        record_for[evtype] = {["count"] = 0, ["error"] = 0}
    end

    if record_for[evtype]["count"] == nil then
        record_for[evtype]["count"] = count
    else
        record_for[evtype]["count"] = record_for[evtype]["count"] + 1
    end

    if error == true then
        if record_for[evtype]["error"] == nil then
            record_for[evtype]["error"] = 1
        else
            record_for[evtype]["error"] = record_for[evtype]["error"] + 1
        end
    end

    if record_for[evtype]["latency"] == nil then
        record_for[evtype]["latency"] = latency
    else
        record_for[evtype]["latency"] = record_for[evtype]["latency"] + latency
    end


    return true
end

-- http://stackoverflow.com/questions/15706270/sort-a-table-in-lua?answertab=votes#tab-top
function spairs(t, order)
    -- collect the keys
    local keys = {}
    for k in pairs(t) do keys[#keys+1] = k end

    -- if order function given, sort by it by passing the table and keys a, b,
    -- otherwise just sort the keys
    if order then
        table.sort(keys, function(a,b) return order(t, a, b) end)
    else
        table.sort(keys)
    end

    -- return the iterator function
    local i = 0
    return function()
        i = i + 1
        if keys[i] then
            return keys[i], t[keys[i]]
        end
    end
end

-- Interval callback, emits the output
function on_capture_end()
    terminal.clearscreen()
    terminal.moveto(0 ,0)
    terminal.showcursor()

    header = string.format("%5s   %5s  %5s   %-10s", "Latency(ms)", "Counts", "Errors", "System Calls")
    print(header)
    print("----------------------------------------------")

    local temp_counter = 0

    for x, y in spairs(record_for, function(t, a, b) return t[b].error < t[a].error end) do
       line = string.format("%7.2f %11d %7d    %-20s",
           y.latency/1000, y.count, y.error, x)
       print(line)

        temp_counter = temp_counter + 1
        if temp_counter == TOP_NUMBER then
	    break
        end
    end
    return true
end
