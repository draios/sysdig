-- Chisel description
description = "print the standard input of any process on screen. Combine this script with a filter to limit the output to a specific process or pid.";
short_description = "print stdin";
category = "IO";

args = {}

-- Initialization callback
function init()
	-- Request the fileds that we need
	fbuf = sysdig.request_field("evt.rawarg.data")

	-- set the filter
	sysdig.set_filter("fd.num=0 and evt.is_io=true")
	
	return true
end

-- Event parsing callback
function on_event()
	buf = evt.field(fbuf)
	
	if buf ~= nil then
		print(buf)
	end
	
	return true
end
