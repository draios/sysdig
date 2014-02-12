-- Chisel description
description = "Shows the top processes in terms of total (in+out) bytes to disk, once per second";
short_description = "top processes by total disk bytes";
category = "IO";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

require "common"

procs = {}

-- Initialization callback
function init()
	-- Request the fields we need
	fbytes = sysdig.request_field("evt.rawarg.res")
	ftime = sysdig.request_field("evt.time.s")
	fpname = sysdig.request_field("proc.name")

	-- set the filter
	sysdig.set_filter("evt.is_io=true and (fd.type=ipv4 or fd.type=ipv6)")
	
	-- set a 1s callback
	sysdig.set_interval_s(1)
	
	return true
end

-- Event parsing callback
function on_event()
	bytes = evt.field(fbytes)

	if bytes ~= nil and bytes > 0 then
		pname = evt.field(fpname)

		if pname ~= nil then
			entryval = procs[pname]
			
			if entryval == nil then
				procs[pname] = bytes
			else
				procs[pname] = procs[pname] + bytes
			end
		end
	end

	return true
end

-- Interval callback, emits the ourput
function on_interval()
	etime = evt.field(ftime)
	sorted_procs = pairs_top_by_val(procs, TOP_NUMBER, function(t,a,b) return t[b] < t[a] end)

	print("--" .. etime .. "------------------------------------------")
	for k,v in sorted_procs do
		print(extend_string(format_bytes(v), 10) .. k)
	end
	
	procs = {}
	return true
end
