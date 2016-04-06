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

-- Chisel description
description = "Sort the list of the processes that use the most network bandwidth. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown."
short_description = "Top processes by network I/O"
category = "Net"

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()


	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	if print_container then
		chisel.exec("table_generator",
					"proc.name,proc.pid,thread.vtid,container.name",
					"Process,Host_pid,Container_pid,container.name",
					"evt.rawarg.res",
					"Bytes",
					"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true",
					"100",
					"bytes")
	else
		chisel.exec("table_generator",
					"proc.name,proc.pid",
					"Process,PID",
					"evt.rawarg.res",
					"Bytes",
					"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true",
					"100",
					"bytes")
	end

		
	return true
end
