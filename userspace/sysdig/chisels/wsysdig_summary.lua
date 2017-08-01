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
description = "internal chisel, creates the json for the wsysdig summary page."
short_description = "wsysdig summary generator"
category = "NA"
hidden = true

-- Chisel argument list
args = {}

local json = require ("dkjson")
local gsummary = {} -- The global summary
local ssummary = {} -- Last sample's summary
local nintervals = 0

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

function reset_summary(s)
	s.nSpawnedProcs = 0
	s.nFileOpensAll = 0
	s.nFileOpensWrite = 0
	s.nSysFileOpensAll = 0
	s.nSysFileOpensWrite = 0
end

function add_summaries(dst, src)
	dst.nSpawnedProcs = dst.nSpawnedProcs + src.nSpawnedProcs
	dst.nFileOpensAll = dst.nFileOpensAll + src.nFileOpensAll
	dst.nFileOpensWrite = dst.nFileOpensWrite + src.nFileOpensWrite
	dst.nSysFileOpensAll = dst.nSysFileOpensAll + src.nSysFileOpensAll
	dst.nSysFileOpensWrite = dst.nSysFileOpensWrite + src.nSysFileOpensWrite
end

function string.starts(big_str, small_str)
   return string.sub(big_str, 1, string.len(small_str)) == small_str
end

function is_system_dir(filename)
	if string.starts(filename, '/bin/') or
		string.starts(filename, '/sbin/') or
		string.starts(filename, '/boot/') or
		string.starts(filename, '/etc/') or
		string.starts(filename, '/lib') or
		string.starts(filename, '/usr/bin/') or
		string.starts(filename, '/usr/sbin/') or
		string.starts(filename, '/usr/share/') or
		string.starts(filename, '/usr/lib')
	then
		return true
	end

	return false
end

-- Initialization callback
function on_init()
    chisel.set_interval_ns(100000000)

    reset_summary(gsummary)
    reset_summary(ssummary)

	-- set the following fields on_event()
	fetype = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir")
	frawres = chisel.request_field("evt.rawres")
	ffdname = chisel.request_field("fd.name")
	fflags = chisel.request_field("evt.arg.flags")
	fcontainername = chisel.request_field("container.name")
	fcontainerid = chisel.request_field("container.id")

	print('{"slices": [')
	return true
end

-- Event callback
function on_event()
	local etype = evt.field(fetype)
	local dir = evt.field(fdir)
	local rawres = evt.field(frawres)
	local fdname = evt.field(ffdname)

	if dir ~= nil and dir == '<' then
		if rawres ~= nil and rawres >= 0 then
			if etype == 'execve' then
				ssummary.nSpawnedProcs = ssummary.nSpawnedProcs + 1
			elseif etype == 'open' or etype == 'openat' then
				local flags = evt.field(fflags)
				if flags == nil then
					return
				end

				ssummary.nFileOpensAll = ssummary.nFileOpensAll + 1

				if string.find(flags, 'O_RDWR') or string.find(flags, 'O_WRONLY') then
					ssummary.nFileOpensWrite = ssummary.nFileOpensWrite + 1
				end

				if is_system_dir(fdname) then
					ssummary.nSysFileOpensAll = ssummary.nSysFileOpensAll + 1

					if string.find(flags, 'O_RDWR') or string.find(flags, 'O_WRONLY') then
						ssummary.nSysFileOpensWrite = ssummary.nSysFileOpensWrite + 1
					end
				end
			end
		end
	end

	return true
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)	
	add_summaries(gsummary, ssummary)
	reset_summary(ssummary)

	if nintervals % 20 == 0 then
		print('{"progress": ' .. sysdig.get_read_progress() .. ' },')
	end
	nintervals = nintervals + 1

	return true
end

-- Called by the engine at the end of the capture
function on_capture_end(ts_s, ts_ns, delta)
	add_summaries(gsummary, ssummary)
	local sstr = json.encode(gsummary, { indent = true })
--	print(sstr)

--print(sysdig.get_evtsource_name())
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'

	os.execute('rm -fr ' .. dirname .. " 2> /dev/null")
	os.execute('mkdir ' .. dirname .. " 2> /dev/null")

	local f = io.open(dirname .. '/summary.json', "w")
	if f == nil then
		print('{"progress": 100, "error": "can\'t create the trace file index" }')
		print(']}')
		return false
	end

	f:write(sstr)
	f:close()

	print('{"progress": 100}')
	print(']}')

	return true
end
