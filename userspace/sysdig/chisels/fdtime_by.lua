--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Gropus FD activity based on the given filter field, and returns the keys where most time was spent. For example, this script can be used to list the processes or files that caused the biggest I/O latency."
short_description = "FD time group by"
category = "IO"

-- Chisel argument list
args = 
{
	{
		name = "key", 
		description = "the filter field used for grouping", 
		argtype = "string"
	},
}

-- The number of items to show
TOP_NUMBER = 10
key_fld = ""

-- Argument notification callback
function on_set_arg(name, val)
	if name == "key" then
		key_fld = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	chisel.exec("table_generator",
		key_fld, 
		key_fld,
		"evt.latency",
		"Time",
		"evt.is_io=true", 
		"time")
		"" .. TOP_NUMBER,
	return true
end
