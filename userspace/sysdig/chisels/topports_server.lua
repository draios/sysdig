-- Chisel description
description = "Shows the top TCP/UDP server ports in terms of total (in+out) bandwidth.";
short_description = "top server ports by total bytes";
category = "net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 100

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("fdbytes_by_internal", "fd.sport", "fd.type=ipv4 or fd.type=ipv6", "" .. TOP_NUMBER)
	return true
end
