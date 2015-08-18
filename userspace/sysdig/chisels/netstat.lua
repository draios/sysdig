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
description = "Print the system network connections, with an output that is similar to the one of netstat. Output is at a point in time; adjust this in the filter. It defaults to time of evt.num=0";
short_description = "List (and optionally filter) network connections.";
category = "System State";
		
-- Argument list
args =
{
	{
		name = "filter",
		description = "A sysdig-like filter expression that allows restricting the FD list. E.g. 'proc.name=foo and fd.port=80'.",
		argtype = "filter",
		optional = true
	}
}

-- Argument initialization Callback
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
local filter = "(fd.type=ipv4)"
local match = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "filter" then
		filter = filter .. "and (" .. val .. ")"
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	return true
end

-- Final chisel initialization
function on_capture_start()	
	capturing = true
	return true
end

-- Event parsing callback
function on_event()
	sysdig.end_capture()
	match = true
	return false
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	if not capturing then
		return
	end
	
	if match == false then
		print("empty capture or no event matching the filter")
		return
	end

	local ttable = sysdig.get_thread_table(filter)

	print(extend_string("Proto", 6) ..
		extend_string("Server Address", 25) ..
		extend_string("Client Address", 25) ..
		extend_string("State", 15) ..
		"TID/PID/Program Name")

	for tid, proc in pairs(ttable) do
		local fdtable = proc.fdtable
		
		for fd, fdinfo in pairs(fdtable) do
			local cip = fdinfo.cip
			local cport = fdinfo.cport
			local state = "ESTABLISHED"

			if cip == nil then
				cip = "0.0.0.0"
				cport = "*"
				state = "LISTEN"
			end

			print(extend_string(fdinfo.l4proto, 6) ..
				extend_string(fdinfo.sip .. ":" .. fdinfo.sport, 25) ..
				extend_string(cip .. ":" .. cport, 25) ..
				extend_string(state, 15) ..
				tid .. "/" .. proc.pid .. "/" .. proc.comm
				)
		end
	end
end
