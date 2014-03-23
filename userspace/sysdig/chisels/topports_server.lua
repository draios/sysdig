--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Shows the top TCP/UDP server ports in terms of total (in+out) bandwidth.";
short_description = "top server ports by total bytes";
category = "net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 100

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("table_generator", 
		"fd.sport",
		"Server Port",
		"evt.rawarg.res",
		"Bytes",
		"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true", 
		"" .. TOP_NUMBER,
		"bytes")
	return true
end
