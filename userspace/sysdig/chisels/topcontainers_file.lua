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
description = "Shows the top containers in terms of total (in+out) bytes to disk."
short_description = "Top containers by R+W disk bytes"
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
		"container.name",
		"container.name",
		"evt.rawarg.res",
		"Bytes",
		"fd.type=file and evt.is_io=true and container.name!=host",
		"" .. TOP_NUMBER,
		"bytes")
	return true
end
