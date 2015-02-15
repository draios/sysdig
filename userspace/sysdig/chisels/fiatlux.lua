--[[
Copyright (C) 2015 Jess Males.
 
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
description = "Filter out all pre-existing processes from subsequent trace"
short_description = "ignore anything from start of trace"
category = "misc"

-- Chisel argument list
args = {}

preexisting = {}

-- provide the current filter state
function build_filter()
    -- ASSUMPTION: there's always at least one thread preexisting
    local cur = "evt.type=exit or (" 
    local count = 0
    for tid, val in pairs(preexisting) do
        if count ~= 0 then
            cur = cur .. " and"
        end
        cur = cur .. " thread.tid!=" .. tid

        count = count + 1
    end
    cur = cur .. " )"

    --Debugging aid:  io.stderr:write("setting filter: " .. cur .. "\n")
    return cur
end

-- Chisel functionality
function on_init()
    ftype = chisel.request_field("evt.type")
    ftid = chisel.request_field("thread.tid")

    chisel.set_event_formatter("%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args")
    return true
end

function on_capture_start()
    -- get_thread_table
    local ttable = sysdig.get_thread_table()

    -- populate 'preexisting' table with all existing threads
    for tid, proc in pairs(ttable) do
        preexisting[tid] = true
    end

    -- set filter for those pids except process exit
    chisel.set_filter(build_filter())

    return true
end

function on_event()
    if evt.field(ftype) == "exit" then
        -- pop pid from existing_threads[]
        local tid = evt.field(ftid)
        preexisting[tid] = nil
        -- reset filter
        chisel.set_filter(build_filter())

        -- we don't want to print exit events, so...
        return false
    end

    return true
end
