-- Chisel description
description = "print the data read and written for any FD. Combine this script with a filter to restrict what it shows.";
short_description = "echo FDs";
category = "IO";

args = {}

require "common"

-- Initialization callback
function on_init()
	-- Request the fileds that we need
	fbuf = chisel.request_field("evt.rawarg.data")
	fisread = chisel.request_field("evt.is_io_read")
	fres = chisel.request_field("evt.rawarg.res")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)
	
	-- set the filter
	chisel.set_filter("evt.is_io=true and evt.dir=<")
	
	return true
end

-- Event parsing callback
function on_event()
	buf = evt.field(fbuf)
	isread = evt.field(fisread)
	res = evt.field(fres)

	if res <= 0 then
		return true
	end
	
	if isread then
		print("------ Read " .. format_bytes(res))
	else
		print("------ Write " .. format_bytes(res))
	end
	
	if buf ~= nil then
		print(buf)
	end
	
	return true
end
