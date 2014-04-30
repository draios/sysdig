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
description = "list the processes that have finished running, along with their execution time, and color every line based on the total process run time";
short_description = "Show process execution time";
category = "Performance";

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"

local THRESHOLD_YELLOW_NS = 3000000000
local THRESHOLD_RED_NS = 10000000000

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fetype = chisel.request_field("evt.type")
	fexe = chisel.request_field("proc.name")
	fargs = chisel.request_field("proc.args")
	fdtime = chisel.request_field("evt.time.s")
	fduration = chisel.request_field("proc.duration")

	-- set the filter
	chisel.set_filter("evt.type=procexit")
	
	return true
end

-- Event parsing callback
function on_event()
	local dtime = evt.field(fdtime)
	local duration = evt.field(fduration)
	
	if duration ~= nil then
		local color = terminal.green
		
		if duration > THRESHOLD_RED_NS then
			color = terminal.red
		elseif duration > THRESHOLD_YELLOW_NS then
			color = terminal.yellow
		end
		
		print(color .. format_time_interval(duration) .. ") " .. evt.field(fexe) .. " " .. evt.field(fargs))
	end
	
	return true
end

function on_capture_end()
	print(terminal.reset)
end
