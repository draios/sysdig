--[[
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
description = "This chisel prints the open file descriptors for every process in the system, with an output that is very similar to the one of lsof";
short_description = "List the open file descriptors.";
category = "System State";
		   
-- Argument list
args = {}

-- Imports and globals
require "common"
local dctable = {}
local capturing = false

-- Argument notification callback
function on_set_arg(name, val)
    if name == "dump_file_name" then
		do_dump = true
        dump_file_name = val
        return true
    end

    return false
end

-- Initialization callback
function on_init()
	return true
end

function on_capture_start()	
	capturing = true
	return true
end

-- Event parsing callback
function on_event()		
	return false
end

function on_capture_end()
	if not capturing then
		return
	end
	
	local ttable = sysdig.get_thread_table()

	print(extend_string("COMMAND", 20) ..
		extend_string("PID", 8) ..
		extend_string("TID", 8) ..
		extend_string("USER", 8) ..
		extend_string("FD", 8) ..
		extend_string("TYPE", 12) ..
		"NAME")

	for tid, proc in pairs(ttable) do
		local fdtable = proc.fdtable

		for fd, fdinfo in pairs(fdtable) do
			print(extend_string(proc.comm, 20) ..
				extend_string(tostring(proc.pid), 8) ..
				extend_string(tostring(tid), 8) ..
				extend_string(proc.username, 8) ..
				extend_string(tostring(fd), 8) ..
				extend_string(tostring(fdinfo.type), 12) ..
				tostring(fdinfo.name))
		end
	end
end
