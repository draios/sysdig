--[[
Copyright (C) 2013-2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Reports every attempt to execute bash in a way that exploits the shellshock vulnerability (http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271). For every attempt, the chisel reports the time, the name of the process trying to run bash, and its PID.";
short_description = "print shellshock attacks";
category = "Security";

args = {}

require "common"

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fpname = chisel.request_field("proc.pname")
	fppid = chisel.request_field("proc.ppid")
	fpid = chisel.request_field("proc.pid")
	fenv = chisel.request_field("evt.arg.environment")
	fetime = chisel.request_field("evt.time")

	-- set the filter
	chisel.set_filter("proc.name=bash or proc.name=sh and evt.type=execve")
	
	print(extend_string("TIME", 22) ..
		extend_string("PROCNAME", 22) ..
		extend_string("PID", 8) ..
		"FUNCTION")

	return true
end

-- Event parsing callback
function on_event()
	local env = evt.field(fenv)
	local pname = evt.field(fpname)
	local etime = evt.field(fetime)
	local ppid = evt.field(fppid)
	
	if env ~= nil then
		if string.find(env, "%(%) ?{.+") then
			local pid = evt.field(fpid)
			local env_list = sysdig.get_thread_table(filter)[pid].env
			
			for i, v in ipairs(env_list) do
				if string.find(v, "%(%) ?{.+") then
					local command = string.match(v, "%(%).+")

					print(extend_string(etime, 22) ..
						extend_string(pname, 22) ..
						extend_string(tostring(ppid), 8) ..
						command)
					break
				end
			end
		end
	end
	
	return true
end
