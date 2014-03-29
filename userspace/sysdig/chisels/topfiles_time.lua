-- Chisel description
description = "Shows the top files in terms of disk usage."
short_description = "Top files by time"
category = "I/O"

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
		"Tilename",
		"evt.latency",
		"Time",
		"fd.type=file and evt.is_io=true", 
		"" .. TOP_NUMBER,
		"time")
	return true
end
