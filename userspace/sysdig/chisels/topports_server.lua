-- Chisel description
description = "Shows the top TCP/UDP server ports in terms of total (in+out) bandwidth, once per second.";
short_description = "top server ports by total bytes";
category = "net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

require "common"

ports = {}
port_procs = {}

-- Initialization callback
function on_init()
	-- Request the fields we need
	fbytes = chisel.request_field("evt.rawarg.res")
	ffpnum = chisel.request_field("fd.sport")
	ftime = chisel.request_field("evt.time.s")
	fpname = chisel.request_field("proc.name")
	fissrv = chisel.request_field("fd.is_server")

	-- set the filter
	chisel.set_filter("evt.is_io=true and (fd.type=ipv4 or fd.type=ipv6)")
	
	return true
end

-- Event parsing callback
function on_event()
	bytes = evt.field(fbytes)
	issrv = evt.field(fissrv)

	if issrv then
		if bytes ~= nil and bytes > 0 then
			fpnum = evt.field(ffpnum)
			pname = evt.field(fpname)

			if fpnum ~= nil then
				entryval = ports[fpnum]
				
				if entryval == nil then
					ports[fpnum] = bytes
				else
					ports[fpnum] = ports[fpnum] + bytes
				end

				port_procs[fpnum] = pname
			end
		end
	end

	return true
end

-- Interval callback, emits the ourput
function on_capture_end()
	etime = evt.field(ftime)
	sorted_ports = pairs_top_by_val(ports, TOP_NUMBER, function(t,a,b) return t[b] < t[a] end)

	for k,v in sorted_ports do
		print(extend_string(format_bytes(v), 10) .. port_procs[k] .. ")" .. k)
	end
	
	ports = {}
	return true
end
