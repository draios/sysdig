-- Chisel description
description = "Shows the top files in terms of disk usage, once per second.";
short_description = "top files by total bytes";
category = "IO";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

require "common"

files = {}

-- Initialization callback
function on_init()
	-- Request the fields
	fbytes = sysdig.request_field("evt.rawarg.res")
	ffname = sysdig.request_field("fd.name")
	ftime = sysdig.request_field("evt.time.s")

	-- set the filter
	sysdig.set_filter("evt.is_io=true and fd.type=file")
	
	-- set a 1s callback
	sysdig.set_interval_s(1)
	
	return true
end

-- Event parsing callback
function on_event()
	bytes = evt.field(fbytes)

	if bytes ~= nil and bytes > 0 then
		fname = evt.field(ffname)
		
		if fname ~= nil then
			entryval = files[fname]
			
			if entryval == nil then
				files[fname] = bytes
			else
				files[fname] = files[fname] + bytes
			end
		end
	end

	return true
end

-- Interval callback, emits the ourput
function on_interval()
	etime = evt.field(ftime)
	sorted_files = pairs_top_by_val(files, TOP_NUMBER, function(t,a,b) return t[b] < t[a] end)

	print("--" .. etime .. "------------------------------------------")
	for k,v in sorted_files do
		print(extend_string(format_bytes(v), 10) .. k)
	end
	
	files = {}
	return true
end
