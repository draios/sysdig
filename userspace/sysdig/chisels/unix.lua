--[[
Copyright (C) 2017 Gabriel Corona

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
description = "print the data passing through a UNIX socket. Combine this script with a filter to limit the output to a specific process, pid or direction.";
short_description = "Print UNIX socket data";
category = "I/O";

args = {
    {
        name = "sockname",
        description = "The name of the UNIX socket.",
        argtype = "string",
        optional = false
    }
}

local sockname = ""

function on_set_arg(name, val)
    if name == "sockname" then
        sockname = val
        return true
    end
    return false
end

-- Initialization callback
function on_init()
    fbuf = chisel.request_field("evt.rawarg.data")
    fname = chisel.request_field("fd.name")
    sysdig.set_snaplen(2000)
    chisel.set_filter("evt.is_io=true and fd.typechar='u'")
    return true
end

-- Event parsing callback
function on_event()

    local name = evt.field(fname)
        if not (name ~= nil) then
        return true
    end

    local i
    local j
    i,j = string.find(name, " ", 1, true)
    if not (i ~= nil) then
        return true
    end

    local buf = evt.field(fbuf)
     if not (buf ~= nil) then
        return true
    end

    local path = string.sub(name, i + 1)
        if path == sockname then
            print(buf)
        end
    return true

end
