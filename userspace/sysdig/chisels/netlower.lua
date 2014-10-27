--[[
netlower.lua - trace network I/O slower than a given threshold.

USAGE: sysdig -c netlower min_ms
   eg, 
        sysdig -c netlower 1000    # show network I/O slower than 1000 ms.

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
description = "Trace network I/O slower than a threshold, or all network I/O"
short_description = "Trace slow network I/0"
category = "Performance"

-- Chisel argument list
args =
{
    {
        name = "min_msec",
        description = "minimum millisecond threshold for showing network I/O",
        argtype = "int"
    },
}

require "common"

-- Argument notification callback
function on_set_arg(name, val)
	min_ms = parse_numeric_input(val, name)
	return true
end

-- Initialization callback
function on_init()
	-- set the following fields on_event()
	etype = chisel.request_field("evt.type")
	dir = chisel.request_field("evt.dir")
	datetime = chisel.request_field("evt.datetime")
	fname = chisel.request_field("fd.name")
	pname = chisel.request_field("proc.name")
	latency = chisel.request_field("evt.latency")

	-- filter for network I/O
	chisel.set_filter("evt.is_io=true and (fd.type=ipv4 or fd.type=ipv6)")

	print(string.format("%-23.23s %-12.12s %-8s %-12s %s", "TIME",
		"PROCESS", "TYPE", "LATENCY(ms)", "SOCKET"))
	return true
end

-- Event callback
function on_event()
	lat = evt.field(latency) / 1000000
	fn = evt.field(fname)
	if evt.field(dir) == "<" and lat > min_ms then
		print(string.format("%-23.23s %-12.12s %-8s %-12d %s",
			evt.field(datetime), evt.field(pname), evt.field(etype), lat, fn))
	end
	return true
end
