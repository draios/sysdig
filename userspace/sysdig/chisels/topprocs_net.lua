-- Chisel description
description = "Gropus FD activity based on the given filter field, and returns the key that generated the most input+output bytes. For example, this script can be used to list the processes or TCP ports that generated most traffic."
short_description = "FD bytes group by"
category = "IO"

-- Chisel argument list
args = {}

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

-- Initialization callback
function on_init()
	chisel.exec("fdbytes_by_internal", "proc.name", "fd.type=ipv4 or fd.type=ipv6", "100")
	return true
end
