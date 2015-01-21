--[[
scallslower.lua - trace the syscalls slower than a given threshold.

USAGE: sysdig -c scallslower min_ms
   eg, 
        sysdig -c scallslower 1000    # show syscalls slower than 1000 ms.

Copyright (C) 2013-2014 Draios inc.
 
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
description = "Trace syscalls slower than a threshold milliseconds";
short_description = "Trace slow syscalls";
category = "Performance";

-- Chisel argument list
args =
{
    {
        name = "min_msec",
        description = "Minimum milliseconds before which a syscall should complete",
        argtype = "int"
    },
}

require "common"

-- Argument notification callback
function on_set_arg(name, val)
    min_msec = parse_numeric_input(val, name)
    return true
end

-- Initialization callback
function on_init()
	-- set the following fields on_event()
	etype = chisel.request_field("evt.type")
	dir = chisel.request_field("evt.dir")
	datetime = chisel.request_field("evt.datetime")
	pname = chisel.request_field("proc.name")
	latency = chisel.request_field("evt.latency")

	print(string.format("%-23.23s %-23.23s %-20s %s", "TIME",
        "PROCESS", "LATENCY(msec)", "SYSCALL"))
	return true
end

-- Event callback
function on_event()
	lat = evt.field(latency) / 1000000
	if lat > min_msec then
	print(string.format("%-23.23s %-23.23s %-20s %s",
		evt.field(datetime), evt.field(pname), lat, evt.field(etype)))
	end
end
