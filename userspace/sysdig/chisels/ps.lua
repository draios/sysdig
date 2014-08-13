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
description = "This chisel lists the running processes, with an output that is similar to the one of ps.";
short_description = "List (and optionally filter) the machine processes.";
category = "System State";
		   
-- Argument list
args = 
{
	{
		name = "filter",
		description = "a sysdig-like filter expression that allows restricting the FD list. For example 'fd.name contains /etc' shows all the processes that have files open under /etc.", 
		argtype = "filter",
		optional = true
	}
}

function on_set_arg(name, val)
	if name == "filter" then
		filter = val
		return true
	end

	return false
end

-- Imports and globals
require "common"
local dctable = {}
local capturing = false
local filter = nil

-- Argument notification callback
function on_set_arg(name, val)
	if name == "filter" then
		filter = val
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
	sysdig.end_capture()
	return false
end

function on_capture_end(ts_s, ts_ns, delta)
	if not capturing then
		return
	end
	
	local ttable = sysdig.get_thread_table(filter)

	local sorted_ttable = pairs_top_by_val(ttable, 0, function(t,a,b) return a < b end)
	
	print(extend_string("TID", 8) ..
		extend_string("PID", 8) ..
		extend_string("USER", 12) ..
		extend_string("CMD", 20))

	for tid, proc in sorted_ttable do
		local fdtable = proc.fdtable
		
		print(
			extend_string(tostring(tid), 8) ..
			extend_string(tostring(proc.pid), 8) ..
			extend_string(proc.username, 12) ..
			proc.comm
			)
	end
end
