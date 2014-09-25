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
description = "reports every attempt to execute bash in a way that exploits the shellshock vulnerability (http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271). For every attempt, the chisel reports the time, the name of the process trying to run bash, and its PID.";
short_description = "print shellshock attacks";
category = "Security";

args = {}

require "common"

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fpname = chisel.request_field("proc.pname")
	fppid = chisel.request_field("proc.ppid")
	fenv = chisel.request_field("proc.env")
	fetime = chisel.request_field("evt.time")

	-- set the filter
	chisel.set_filter("proc.name=bash or proc.name=sh and evt.type=execve")
	
	print(extend_string("TIME", 22) ..
		extend_string("PROCNAME", 25) ..
		"PID")

	return true
end

-- Event parsing callback
function on_event()
	env = evt.field(fenv)
	pname = evt.field(fpname)
	etime = evt.field(fetime)
	ppid = evt.field(fppid)
	
	if env ~= nil then
	
		if string.find(env, "%(%) ?{.+}.+") then
			print(extend_string(etime, 22) ..
				extend_string(pname, 25) ..
				ppid)
		end
	end
	
	return true
end
