--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Shows the top processes in terms of system call errors."
short_description = "top processes by number of errors"
category = "errors"

-- Chisel argument list
args = {}

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("table_generator", 
		"proc.name",
		"Process",
		"evt.count",
		"#Errors",
		"evt.failed=true", 
		"100",
		"none")
	return true
end
