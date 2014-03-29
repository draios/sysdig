-- Chisel description
description = "Sorthed list of the processes that use the most network bandwidth."
short_description = "Top processes by network I/O"
category = "Net"

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()
	chisel.exec("table_generator", 
		"proc.name",
		"Process",
		"evt.rawarg.res",
		"Bytes",
		"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true", 
		"100",
		"bytes")
		
	return true
end
