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
description = "lists every command that users launch interactively (e.g. from bash) and every directory users visit";
short_description = "Display interactive user activity";
category = "Security";

-- Chisel argument list
args = 
{
	{
		name = "max_depth",
		description = "the maximum depth to show in the hierarchy of processes", 
		argtype = "int",
        optional = true
	}
}

require "common"

MAX_ANCESTOR_NAVIGATION = 16
max_depth = -1

-- Argument notification callback
function on_set_arg(name, val)
    if name == "max_depth" then
        max_depth = tonumber(val)
        return true
    end

    return false
end

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fetype = chisel.request_field("evt.type")
	fexe = chisel.request_field("proc.exe")
	fargs = chisel.request_field("proc.args")
	fdir = chisel.request_field("evt.arg.path")
	fuser = chisel.request_field("user.name")
	fdtime = chisel.request_field("evt.time.s")
	fpid = chisel.request_field("proc.pid")
	fppid = chisel.request_field("proc.ppid")
	fanames = {}
	fapids = {}

	-- set the filter
	chisel.set_filter("((evt.type=execve and evt.dir=<) or (evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)) and evt.failed=false")
	
	for j = 0, MAX_ANCESTOR_NAVIGATION do
		fanames[j] = chisel.request_field("proc.aname[" .. j .. "]")
		fapids[j] = chisel.request_field("proc.apid[" .. j .. "]")
	end
	
	return true
end

process_tree = {}

-- Event parsing callback
function on_event()
	local user = evt.field(fuser)
	local dtime = evt.field(fdtime)
	local pid = evt.field(fpid)
	local ppid = evt.field(fppid)
	local ischdir = evt.field(fetype) == "chdir"
	local aname
	local icorr = 1

	if ischdir then 
		ppid = pid
		table.insert(fanames, 0, 0)
		table.insert(fapids, 0, 0)
		icorr = 0
	end
	
	if user == nil then
		user = "<NA>"
	end
	
	if not process_tree[ppid] then
		-- No parent pid in the table yet.
		-- Add one and make sure that there's a shell among the ancestors
		process_tree[ppid] = {-1}
		
		for j = 1, MAX_ANCESTOR_NAVIGATION do
			aname = evt.field(fanames[j])
			
			if aname == nil then
				if evt.field(fapids[j]) == nil then
					-- no shell in the ancestor list, hide this command
					break
				end
			elseif string.len(aname) > 2 and aname:sub(-2) == "sh" then
				apid = evt.field(fapids[j])
				if process_tree[apid] then
					process_tree[ppid] = {j - 1, apid}
				else
					process_tree[ppid] = {0, apid}
				end
			end
		end
	end

	if process_tree[ppid][1] == -1 then
		-- the parent process has already been detected as NOT having a shell ancestor
		return true
	end
	
	if not process_tree[pid] then
		process_tree[pid] = {1 + process_tree[ppid][1], process_tree[ppid][2]}
	end

	if max_depth ~= -1 then
		if process_tree[pid][1] > max_depth then
			return true
		end
	end
	
	if ischdir then
		print(extend_string("", 4 * (process_tree[pid][1] - icorr)) .. dtime .. " " .. user .. " " .. process_tree[pid][2] .. ") " .. "cd " .. evt.field(fdir))
	else
		print(extend_string("", 4 * (process_tree[pid][1] - 1)) .. dtime .. " " .. user .. " " .. process_tree[pid][2] .. ") " .. evt.field(fexe) .. " " .. evt.field(fargs))
	end

	return true
end
