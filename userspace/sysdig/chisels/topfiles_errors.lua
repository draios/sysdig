-- Chisel description
description = "Shows the top files in terms of I/O errros."
short_description = "top files by number of errors"
category = "errors"

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
		"Filename",
		"evt.count",
		"#Errors",
		"fd.type=file and evt.failed=true", 
		"100",
		"none")
	return true
end
