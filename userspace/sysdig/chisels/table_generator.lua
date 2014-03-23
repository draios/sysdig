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
short_description = "FD bytes group by"
category = "IO"
hidden = true

-- Chisel argument list
args = 
{
	{
		name = "key", 
		description = "the filter field used for grouping", 
		argtype = "string"
	},
	{
		name = "keydesc", 
		description = "human readable description for the key", 
		argtype = "string"
	},
	{
		name = "value", 
		description = "the value to count for every key", 
		argtype = "string"
	},
	{
		name = "valuedesc", 
		description = "human readable description for the value", 
		argtype = "string"
	},
	{
		name = "filter", 
		description = "the filter to apply", 
		argtype = "string"
	},
	{
		name = "top_number", 
		description = "maximum number of elements to display", 
		argtype = "string"
	},
	{
		name = "result_rendering", 
		description = "how to render the values in the result. Can be 'bytes', 'time' or 'none'.", 
		argtype = "string"
	},
}

require "common"
terminal = require "ansiterminal"

top_number = 0
grtable = {}
key_fld = ""
key_desc = ""
value_fld = ""
value_desc = ""
filter = ""
result_rendering = "none"
islive = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "key" then
		key_fld = val
		return true
	elseif name == "keydesc" then
		key_desc = val
		return true
	elseif name == "value" then
		value_fld = val
		return true
	elseif name == "valuedesc" then
		value_desc = val
		return true
	elseif name == "filter" then
		filter = val
		return true
	elseif name == "top_number" then
		top_number = tonumber(val)
		return true
	elseif name == "result_rendering" then
		result_rendering = val
		return true
	end

	return false
end

function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	fvalue = chisel.request_field(value_fld)
	
	-- set the filter
	if filter == "" then
		chisel.set_filter("evt.is_io=true")
	else
		chisel.set_filter(filter)
	end
	
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
		entryval = grtable[key]

		if entryval == nil then
			grtable[key] = value
		else
			grtable[key] = grtable[key] + value
		end
	end

	return true
end

function on_interval()
	sorted_grtable = pairs_top_by_val(grtable, top_number, function(t,a,b) return t[b] < t[a] end)
	
	etime = evt.field(ftime)
	
	terminal.clearscreen()
	terminal.goto(0, 0)
	print(extend_string(value_desc, 10) .. key_desc)
	print("------------------------------")

	for k,v in sorted_grtable do
		if result_rendering == "none" then
			print(extend_string(v, 10) .. k)
		elseif result_rendering == "bytes" then
			print(extend_string(format_bytes(v), 10) .. k)
		elseif result_rendering == "time" then
			print(extend_string(format_time_interval(v), 10) .. k)
		end
	end

	-- Clear the table
	grtable = {}
	
	return true
end

function on_capture_end()
	if islive then
		terminal.clearscreen()
		terminal.goto(0 ,0)
		terminal.showcursor()
		return true
	end

	sorted_grtable = pairs_top_by_val(grtable, top_number, function(t,a,b) return t[b] < t[a] end)
	
	etime = evt.field(ftime)
	
	print(extend_string(value_desc, 10) .. key_desc)
	print("------------------------------")
	
	for k,v in sorted_grtable do
		if result_rendering == "none" then
			print(extend_string(v, 10) .. k)
		elseif result_rendering == "bytes" then
			print(extend_string(format_bytes(v), 10) .. k)
		elseif result_rendering == "time" then
			print(extend_string(format_time_interval(v), 10) .. k)
		end
	end
	
	return true
end
