--[[
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

-- The number of items to show
TOP_NUMBER = 30

-- Chisel description
description = "Show the top " .. TOP_NUMBER .. " system calls in terms of time spent in each call. You can use filters to restrict this to a specific process, thread or file. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown."
short_description = "Top system calls by time"
category = "Performance"

-- Chisel argument list
args = {}

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    if print_container then
		chisel.exec("table_generator", 
			"evt.type,container.name",
			"Syscall,container.name",
			"evt.latency",
			"Time",
			"", 
			"" .. TOP_NUMBER,
			"time")
    else
		chisel.exec("table_generator", 
			"evt.type",
			"Syscall",
			"evt.latency",
			"Time",
			"", 
			"" .. TOP_NUMBER,
			"time")
    end

	return true
end
