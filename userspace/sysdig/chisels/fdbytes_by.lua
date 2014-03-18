-- Chisel description
description = "Gropus FD activity based on the given filter field, and returns the key that generated the most input+output bytes. For example, this script can be used to list the processes or TCP ports that generated most traffic.";
short_description = "FD bytes group by";
category = "IO";

-- Chisel argument list
args = 
{
	{
		name = "key", 
		description = "the filter field used for grouping", 
		argtype = "string"
	},
}

-- The number of items to show
TOP_NUMBER = 0

require "common"

grtable = {}
key_fld = ""

-- Argument notification callback
function on_set_arg(name, val)
	if name == "key" then
		key_fld = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	ffdnum = chisel.request_field("fd.num")
	ffdname = chisel.request_field("fd.name")
	fbytes = chisel.request_field("evt.rawarg.res")
	
	-- set the filter
	chisel.set_filter("evt.is_io=true and fd.type=file")
	
	return true
end

-- Event parsing callback
function on_event()
	key = evt.field(fkey)
	fdnum = evt.field(ffdnum)
	fdname = evt.field(ffdname)
	bytes = evt.field(fbytes)

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

-- Interval callback, emits the ourput
function on_capture_end()
	sorted_grtable = pairs_top_by_val(grtable, TOP_NUMBER, function(t,a,b) return t[b] < t[a] end)
	
	etime = evt.field(ftime)

	for k,v in sorted_grtable do
		print(k, format_bytes(v))
	end
	
	return true
end
