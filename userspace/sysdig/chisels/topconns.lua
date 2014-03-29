-- Chisel description
description = "Shows the top network connections in terms of total (in+out) bandwidth.";
short_description = "top network connections by total bytes";
category = "Net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 10

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("table_generator", 
		"fd.name",
		"Tuple",
		"evt.rawarg.res",
		"Bytes",
		"(fd.type=ipv4 or fd.type=ipv6) and evt.is_io=true", 
		"" .. TOP_NUMBER,
		"bytes")
	return true
end
