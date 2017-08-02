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
local file_cache_exists = false

function on_set_arg(name, val)
	return false
end

-------------------------------------------------------------------------------
-- Summary handling helpers
-------------------------------------------------------------------------------
function create_category()
	return {tot=0, max=0, timeLine={}}
end

function reset_summary(s)
	s.SpawnedProcs = create_category()
	s.FileOpensAll = create_category()
	s.FileOpensWrite = create_category()
	s.SysFileOpensAll = create_category()
	s.SysFileOpensWrite = create_category()
end

function add_summaries(ts_s, ts_ns, dst, src)
	for k, v in pairs(src) do
		dst[k].tot = dst[k].tot + v.tot
		if v.tot > dst[k].max then
			dst[k].max = v.tot 
		end
		local tl = dst[k].timeLine
		tl[#tl+1] = {t = sysdig.make_ts(ts_s, ts_ns), v=v.tot}
	end
end

-------------------------------------------------------------------------------
-- Helpers to dig into event data
-------------------------------------------------------------------------------
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

-------------------------------------------------------------------------------
-- Initialization callbacks
-------------------------------------------------------------------------------
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

function on_capture_start()
--[[
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'
	local f = io.open(dirname .. '/summary.json', "r")
	if f ~= nil then
		f:close()
		file_cache_exists = true
		sysdig.end_capture()
	end
]]--
	return true
end

-------------------------------------------------------------------------------
-- Event callback
-------------------------------------------------------------------------------
function on_event()
	local etype = evt.field(fetype)
	local dir = evt.field(fdir)
	local rawres = evt.field(frawres)
	local fdname = evt.field(ffdname)

	if dir ~= nil and dir == '<' then
		if rawres ~= nil and rawres >= 0 then
			if etype == 'execve' then
				ssummary.SpawnedProcs.tot = ssummary.SpawnedProcs.tot + 1
			elseif etype == 'open' or etype == 'openat' then
				local flags = evt.field(fflags)
				if flags == nil then
					return
				end

				ssummary.FileOpensAll.tot = ssummary.FileOpensAll.tot + 1

				if string.find(flags, 'O_RDWR') or string.find(flags, 'O_WRONLY') then
					ssummary.FileOpensWrite.tot = ssummary.FileOpensWrite.tot + 1
				end

				if is_system_dir(fdname) then
					ssummary.SysFileOpensAll.tot = ssummary.SysFileOpensAll.tot + 1

					if string.find(flags, 'O_RDWR') or string.find(flags, 'O_WRONLY') then
						ssummary.SysFileOpensWrite.tot = ssummary.SysFileOpensWrite.tot + 1
					end
				end
			end
		end
	end

	return true
end

-------------------------------------------------------------------------------
-- Periodic timeout callback
-------------------------------------------------------------------------------
function on_interval(ts_s, ts_ns, delta)	
	add_summaries(ts_s, ts_ns, gsummary, ssummary)
	reset_summary(ssummary)

	if nintervals % 20 == 0 then
		print('{"progress": ' .. sysdig.get_read_progress() .. ' },')
		io.flush(stdout)
	end
	nintervals = nintervals + 1

	return true
end

-------------------------------------------------------------------------------
-- End of capture output generation
-------------------------------------------------------------------------------
function build_output()
	local res = {}

	res[#res+1] = {
		name = 'Spawned Processes',
		desc = 'Number of new programs that have been executed during the observed interval',
		data = gsummary.SpawnedProcs
	}

	res[#res+1] = {
		name = 'Files Opened',
		desc = 'XXX',
		data = gsummary.FileOpensAll
	}

	res[#res+1] = {
		name = 'Files Opened for Writing',
		desc = 'XXX',
		data = gsummary.FileOpensWrite
	}

	res[#res+1] = {
		name = 'System Files Opened',
		desc = 'XXX',
		data = gsummary.SysFileOpensAll
	}

	res[#res+1] = {
		name = 'System Files Opened for Writing',
		desc = 'XXX',
		data = gsummary.SysFileOpensWrite
	}

	resstr = json.encode(res, { indent = true })
	return resstr
end

-- Callback called by the engine at the end of the capture
function on_capture_end(ts_s, ts_ns, delta)
	local sstr = ''
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'

--	if file_cache_exists then
if false then
		local f = io.open(dirname .. '/summary.json', "r")
		if f == nil then
			print('{"progress": 100, "error": "can\'t read the trace file index" }')
			print(']}')
			return false
		end

		sstr = f:read("*all")
		f:close()
	else
		add_summaries(ts_s, ts_ns, gsummary, ssummary)
		sstr = build_output()

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
	end

	print('{"progress": 100, "data": '.. sstr ..'}')
	print(']}')

	return true
end
