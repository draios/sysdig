-- Chisel description
description = "Shows the top network connections in terms of total (in+out) bandwidth, once per second";
short_description = "top connections by total bytes";
category = "net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

require "common"

connections = {}
connection_procs = {}

-- Initialization callback
function on_init()
	-- Request the fields we need
	fbytes = sysdig.request_field("evt.rawarg.res")
	ffname = sysdig.request_field("fd.name")
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
		fname = evt.field(ffname)
		pname = evt.field(fpname)

		if fname ~= nil then
			entryval = connections[fname]
			
			if entryval == nil then
				connections[fname] = bytes
			else
				connections[fname] = connections[fname] + bytes
			end

			connection_procs[fname] = pname
		end
	end

	return true
end

-- Interval callback, emits the ourput
function on_interval()
	etime = evt.field(ftime)
	sorted_connections = pairs_top_by_val(connections, TOP_NUMBER, function(t,a,b) return t[b] < t[a] end)

	print("--" .. etime .. "------------------------------------------")
	for k,v in sorted_connections do
		print(extend_string(format_bytes(v), 10) .. connection_procs[k] .. ")" .. k)
	end
	
	connections = {}
	return true
end
