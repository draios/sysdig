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
description = "List the running containers and the metadata";
short_description = "List the running containers";
category = "System State";
		
-- Argument list
args =
{
		{
				name = "desc",
				description = "Prints the result set as a data structure",
				argtype = "string",
				optional = true
		}
}

-- Imports and globals
require "common"
local dctable = {}
local capturing = false
local filter = nil
local desc = false

-- Argument initialization Callback
function on_set_arg(name, val)
		if name == "desc" and val == "desc" then
				desc = true
				return true
		end

		return false
end

-- Initialization callback
function on_init()
	return true
end

-- Event parsing callback
function on_event()
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
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
		if not capturing then
				return
		end

	local ttable = sysdig.get_container_table(filter)

	-- Print out the result set as a data structure
		if ( desc ) then
		print(st(ttable))
		else
	-- Print out the information in a tabular format

		local sorted_ttable = pairs_top_by_val(ttable, 0, function(t,a,b) return a < b end)

		print( extend_string("container.type", 15) ..
			extend_string("container.image", 16) ..
			extend_string("container.name", 20 ) ..
			extend_string("container.id", 13) )
		print( extend_string("---------------", 15) ..
			extend_string("----------------", 16) ..
			extend_string("--------------------", 20 ) ..
			extend_string("-------------", 13) )

		for key, val in sorted_ttable do
			print(extend_string(tostring(val.type), 15) ..
			extend_string(tostring(val.image), 16) ..
			extend_string(tostring(val.name), 20) ..
			extend_string(tostring(val.id), 13)
			)
		end
	end
end
