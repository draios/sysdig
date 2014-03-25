--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Given two filter fields, a key and a value, this chisel creates and renders to the screen a table."
short_description = "Top processes by CPU usage"
category = "CPU"
hidden = true

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("table_generator", 
		"proc.name",
		"Process",
		"thread.exectime",
		"CPU%",
		"evt.type=switch", 
		"" .. TOP_NUMBER,
		"timepct")
	return true
end
