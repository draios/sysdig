--[[
memcachelog.lua - show most used memcached keys.

USAGE: sysdig -c memcachelog <get|set>
  eg,

  sysdig -c memcachelog             # show memcached get/set utilization
  sysdig -c memcachelog get         # show memcached only get utilization
  sysdig -c memcachelog set         # show memcached only set utilization
  sysdig -c memcachelog 'set 1000'  # show memcached set utilization which object's size is higher than 1000

By default it will print both methods.

Copyright (C) 2015 Donatas Abraitis.

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
description = "Show a log of memcached commands (get/set)"
short_description = "memcached requests log"
category = "Application"

-- Chisel argument list
args =
{
  {
    name = "method",
    description = "get/set",
    optional = true
  },
  {
    name = "size",
    description = "object size",
    optional = true
  }
}

-- Helpers --
function split(s, delimiter)
  result = {};
  for match in (s..delimiter):gmatch("(.-)"..delimiter) do
    table.insert(result, match);
  end
  return result;
end

-- Argument notification callback
function on_set_arg(name, val)
    if name == "method" then
      opt_method = val
      return true
    elseif name == "size" then
      opt_size = tonumber(val)
      return true
    end
    return false
end

-- Initialization callback
function on_init()
    util = {}
    start_time = os.time()
    sysdig.set_filter("(fd.sport=11211 or proc.name=memcached) and evt.is_io=true")
    sysdig.set_snaplen(4096)
    data = chisel.request_field("evt.arg[1]")
    datetime = chisel.request_field("evt.datetime")
    return true
end

-- Event callback
function on_event()
  local data = evt.field(data)
  local line = split(data, " ")
  if string.match(line[1], '^[gs]et') ~= nil then
    local method = line[1]
    local key = line[2]
    local size = tonumber(line[5]) or 0
    if key ~= nil then
      if opt_method ~= nil and opt_method ~= method then
        return true
      end
      if opt_method == 'set' and size < opt_size then
        return true
      end
      print(string.format("%s method=%s size=%dB key=%s",
              evt.field(datetime),
              method,
              size,
              key
      ))
    end
  end
  return true
end
