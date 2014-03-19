-- Chisel description
description = "Shows the top network connections in terms of total (in+out) bandwidth";
short_description = "top connections by total bytes";
category = "net";

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
	chisel.exec("fdbytes_by_internal", "fd.name", "fd.type=ipv4 or fd.type=ipv6", "" .. TOP_NUMBER)
	return true
end
