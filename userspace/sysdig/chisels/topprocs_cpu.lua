--[[
Copyright (C) 2013-2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Given two filter fields, a key and a value, this chisel creates and renders to the screen a table."
short_description = "Top processes by CPU usage"
category = "CPU"
hidden = true

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"

top_number = 10
grtable = {}
key_fld = "proc.name"
key_desc = "Process"
value_fld = "thread.exectime"
value_desc = "CPU%"
result_rendering = "timepct"
islive = false
lastts_s = 0
lastts_ns = 0
reminder = 0

function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	fvalue = chisel.request_field(value_fld)
	
	chisel.set_filter("evt.type=switch")
	
	return true
end

function on_capture_start()
	islive = sysdig.is_live()

	if islive then
		chisel.set_interval_s(1)
		terminal.clearscreen()
		terminal.hidecursor()
	end

	return true
end

function on_event()
	key = evt.field(fkey)
	value = evt.field(fvalue)

	if key ~= nil and value ~= nil and value > 0 then
		if grtable[key] == nil then
			grtable[key] = value - reminder
		else
			grtable[key] = grtable[key] + value - reminder
		end
		
		reminder = 0
		
		lastts_s, lastts_ns = evt.get_ts()
	end

	return true
end

function on_interval(ts_s, ts_ns, delta)
	terminal.clearscreen()
	terminal.goto(0, 0)
	
	if lastts_s ~= 0 then
		reminder = 1000000000 - lastts_ns

		if grtable[key] == nil then
			grtable[key] = value
		else
			grtable[key] = grtable[key] + reminder
		end
	end
	
	print_sorted_table(grtable, 1000000, result_rendering)
	
	-- Clear the table
	grtable = {}
	
	return true
end

function on_capture_end(ts_s, ts_ns, delta)
	if islive then
		terminal.clearscreen()
		terminal.goto(0 ,0)
		terminal.showcursor()
		return true
	end
	
	print_sorted_table(grtable, delta, result_rendering)
	
	return true
end

