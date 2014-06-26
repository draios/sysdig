--[[
fileslower.lua - trace file I/O slower than a given threshold.

USAGE: sysdig -c fileslower min_ms
   eg,
       sysdig -c fileslower 10		# show file I/O slower than 10 ms
       sysdig -c fileslower 0		# show all file I/O

By default this skips file I/O to /dev. Modify the skip_dev variable in this
chisel to change this behavior.

Note: The file I/O traced is those matched by the sysdig filter:
"evt.is_io=true and fd.type=file".

Copyright (C) 2014 Brendan Gregg.
 
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

description = "Trace file I/O slower than a threshold, or all file I/O";
short_description = "Trace slow file I/O";
category = "Performance";

skip_dev = true		-- skip /dev/... files

args =
{
    {
        name = "min_ms",
        description = "minimum millisecond threshold for showing file I/O",
        argtype = "int"
    },
}

function on_set_arg(name, val)
    min_ms = tonumber(val)
    return true
end

function on_init()
    -- set these fields on_event()
    etype = chisel.request_field("evt.type")
    dir = chisel.request_field("evt.dir")  
    datetime = chisel.request_field("evt.datetime")
    fname = chisel.request_field("fd.name")
    pname = chisel.request_field("proc.name")
    latency = chisel.request_field("evt.latency")

    -- filter for file I/O
    chisel.set_filter("evt.is_io=true and fd.type=file")

    print(string.format("%-23.23s %-12.12s %-8s %7s %s", "TIME",
        "PROCESS", "TYPE", "LAT(ms)", "FILE"))
    return true
end

function on_event()
    lat = evt.field(latency) / 1000000
    fn = evt.field(fname)
    if evt.field(dir) == "<" and lat > min_ms then
        -- filter /dev files if needed
        if skip_dev == false or string.sub(fn, 0, 5) ~= "/dev/" then
            print(string.format("%-23.23s %-12.12s %-8s %7d %s",
                evt.field(datetime), evt.field(pname), evt.field(etype), lat, fn))
        end
    end

    return true
end
