--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "counts the total bytes read from and written to files.";
short_description = "sum of file I/O bytes";
category = "IO";

-- Chisel argument list
args = 
{
}

tot = 0
totin = 0
totout = 0

-- Initialization callback
function on_init()
	-- Request the fields
	fbytes = chisel.request_field("evt.rawarg.res")
	ftime = chisel.request_field("evt.time.s")
	fisread = chisel.request_field("evt.is_io_read")

	-- set the filter
	chisel.set_filter("evt.is_io=true and fd.type=file")
	
	chisel.set_interval_s(1)
	
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

function on_interval()
	etime = evt.field(ftime)
	print(etime .. " in:" .. totin .. " out:" .. totout .. " tot:" .. tot)
	tot = 0
	totin = 0
	totout = 0
	return true
end
