-- Chisel description
description = "lists every command that a specific user launches interactively (e.g. from bash) and every directory the user visits";
category = "Security";

-- Chisel argument list
args = 
{
	{
		name = "username", 
		description = "", 
		argtype = "string"
	},
}

-- Argument notification callback
function set_arg(name, val)
	if name == "username" then
		uname = val
	end
	
	return true
end

-- Initialization callback
function init()
	-- Request the fileds that we need
	etype = sysdig.request_field("evt.type")
	exe = sysdig.request_field("proc.exe")
	args = sysdig.request_field("proc.args")
	dir = sysdig.request_field("evt.arg.path")

	-- set the filter
	sysdig.set_filter("user.name=" .. uname .. " and ((evt.type=execve and proc.name!=bash and proc.parentname=bash) or (evt.type=chdir and evt.dir=< and proc.name=bash))")
	
	return true
end

-- Event parsing callback
function on_event()
	if evt.field(etype) == "chdir" then
		print("cd " .. evt.field(dir))
	else
		print(evt.field(exe) .. " " .. evt.field(args))
	end

	return true
end
