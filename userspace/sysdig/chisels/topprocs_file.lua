-- Chisel description
description = "Shows the top processes in terms of total (in+out) bytes to disk."
short_description = "top processes by total disk bytes"
category = "IO"

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
	chisel.exec("fdbytes_by_internal", "proc.name", "fd.type=file", "" .. TOP_NUMBER)
	return true
end
