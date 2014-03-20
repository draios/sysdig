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
description = "Gropus FD activity based on the given filter field, and returns the key that generated the most input+output bytes."
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
		name = "value", 
		description = "the value to count for every key", 
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
}

require "common"

top_number = 0
grtable = {}
key_fld = ""
value_fld = ""
filter = ""

-- Argument notification callback
function on_set_arg(name, val)
	if name == "key" then
		key_fld = val
		return true
	elseif name == "value" then
		value_fld = val
		return true
	elseif name == "filter" then
		filter = val
		return true
	elseif name == "top_number" then
		top_number = tonumber(val)
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	fvalue = chisel.request_field(value_fld)
	ffdnum = chisel.request_field("fd.num")
	ffdname = chisel.request_field("fd.name")
	
	-- set the filter
	if filter == "" then
		chisel.set_filter("evt.is_io=true")
	else
		chisel.set_filter(filter)
	end
	
	return true
end

-- Event parsing callback
function on_event()
	key = evt.field(fkey)
	fdnum = evt.field(ffdnum)
	fdname = evt.field(ffdname)
	bytes = evt.field(fvalue)

	if key ~= nil and fdnum ~= nil and bytes ~= nil and bytes > 0 and fdnum > 0 and fdname ~= nil and fdname ~= "" then
		entryval = grtable[key]
		fdkey = tostring(fdnum) .. fdname

		if entryval == nil then
			grtable[key] = bytes
		else
			grtable[key] = grtable[key] + bytes
		end
	end

	return true
end

-- Interval callback, emits the output
function on_capture_end()
	sorted_grtable = pairs_top_by_val(grtable, top_number, function(t,a,b) return t[b] < t[a] end)
	
	etime = evt.field(ftime)

	for k,v in sorted_grtable do
		print(k, format_bytes(v))
	end
	
	return true
end
