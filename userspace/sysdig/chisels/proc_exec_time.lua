--[[
USAGE: sysdig -c proc_exec_time  
   eg,

   sysdig -c proc_exec_time                 # show processes that have finished 
   sysdig -c proc_exec_time disable_colors" # show processes that have finished w/ no colors

Copyright (C) 2014 Draios inc.
 
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
description = "List the processes that have finished running, along with their execution time, and color every line based on the total process run time";
short_description = "Show process execution time";
category = "Performance";

-- Chisel argument list
args =
{
    {
        name = "disable_color",
        description = "Set to 'disable_colors' if you want to disable color output",
        argtype = "string",
        optional = true
    },
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

local THRESHOLD_YELLOW_NS = 3000000000
local THRESHOLD_RED_NS = 10000000000

-- Argument notification callback
function on_set_arg(name, val)
    if val == "disable_colors" then
        terminal.enable_color(false)
    end
    return true
end

-- Initialization callback
function on_init()
    -- Request the fields that we need
    fetype = chisel.request_field("evt.type")
    fexe = chisel.request_field("proc.name")
    fargs = chisel.request_field("proc.args")
    fdtime = chisel.request_field("evt.time.s")
    fduration = chisel.request_field("proc.duration")
    fcontainer = chisel.request_field("container.name")

    -- set the filter
    chisel.set_filter("evt.type=procexit")

    print(string.format("%-13.13s %-20.20s %-12.12s %s", 
                        "proc.duration", "container.name", "proc.name", "proc.args"))
    print(string.format("%-13.13s %-20.20s %-12.12s %s", 
                        "-------------", 
                        "--------------------", 
                        "------------", 
                        "--------------------"))
    
    return true
end

-- Event parsing callback
function on_event()
    local dtime = evt.field(fdtime)
    local duration = evt.field(fduration)
    
    if duration ~= nil then
        local color = terminal.green
        
        if duration > THRESHOLD_RED_NS then
            color = terminal.red
        elseif duration > THRESHOLD_YELLOW_NS then
            color = terminal.yellow
        elseif evt.field(fcontainer) ~= "host" then
            -- if the data is assocaited with a container change the color to blue unless a threshold is met
            color = terminal.blue
        end

        -- Appears to be a visually exceptable way to display the output
        print(color .. string.format("%-13.13s %-20.20s %-12.12s %s", format_time_interval(duration), evt.field(fcontainer), evt.field(fexe), evt.field(fargs)))

        -- All of these are viable ways to print output
        --if evt.field(fcontainer) == "host" then    
            --print(color .. string.format("%-10.10s %-20.20s %-12.12s %s", format_time_interval(duration), "", evt.field(fexe), evt.field(fargs)))
            --print(color .. string.format("%-10.10s %-12.12s %s", format_time_interval(duration), evt.field(fexe), evt.field(fargs)))
            --print(color .. format_time_interval(duration) .. ") " .. evt.field(fexe) .. " " .. evt.field(fargs))
        --else
            --print(color .. string.format("%-10.10s %-20.20s %-12.12s %s", format_time_interval(duration), evt.field(fcontainer), evt.field(fexe), evt.field(fargs)))
            --print(color .. format_time_interval(duration) .. ") " .. evt.field(fcontainer) .. " " .. evt.field(fexe) .. " " .. evt.field(fargs))
        --end
    end
    
    return true
end

function on_capture_end()
    print(terminal.reset)
end
