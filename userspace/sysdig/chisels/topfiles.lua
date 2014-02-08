-- Chisel description
description = "counts the total bytes read from and written to any type of FD (disk, socket, pipe...) and prints the result every second";
short_description = "top files by total bytes";
category = "IO";

-- Chisel argument list
args = {}

require "common"

files = {}

-- Initialization callback
function init()
	-- Request the fields
	fbytes = sysdig.request_field("evt.rawarg.res")
	ffname = sysdig.request_field("fd.name")
	ftime = sysdig.request_field("evt.time.s")

	-- set the filter
	sysdig.set_filter("evt.is_io=true and fd.type=file")
	
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
	sorted_files = pairs_top_by_val(files, 10, function(t,a,b) return t[b] < t[a] end)

	print("--" .. etime .. "------------------------------------------")
	for k,v in sorted_files do
		print(extend_string(format_bytes(v), 10) .. k)
	end
	
	files = {}
	return true
end
