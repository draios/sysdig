-- Chisel description
description = "counts the total bytes read from and written to any type of FD (disk, socket, pipe...) and prints the result every second.";
short_description = "sum of all I/O bytes";
category = "IO";

-- Chisel argument list
args = 
{
}

tot = 0
totin = 0
totout = 0

-- Initialization callback
function init()
	-- Request the fields
	fbytes = sysdig.request_field("evt.rawarg.res")
	ftime = sysdig.request_field("evt.time.s")
	fisread = sysdig.request_field("evt.is_io_read")

	-- set the filter
	sysdig.set_filter("evt.is_io=true")
	
	sysdig.set_timeout_s(1)
	
	return true
end

-- Event parsing callback
function on_event()
	bytes = evt.field(fbytes)
	isread = evt.field(fisread)

	if bytes ~= nil and bytes > 0 then
		tot = tot + bytes
		
		if isread then
			totin = totin + bytes
		else
			totout = totout + bytes
		end
	end

	return true
end

function on_timeout()
	etime = evt.field(ftime)
	print(etime .. " in:" .. totin .. " out:" .. totout .. " tot:" .. tot)
	tot = 0
	totin = 0
	totout = 0
	return true
end
