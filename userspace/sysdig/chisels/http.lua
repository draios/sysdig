--[[
Copyright (C) 2015 Luca Marturana

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
description = "Shows http connections";
short_description = "Top http connections";
category = "Net";

-- Chisel argument list
args = {}

-- The number of items to show
TOP_NUMBER = 30

-- Argument notification callback
function on_set_arg(name, val)
    return false
end


-- Initialization callback
function on_init()

    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    chisel.set_filter("evt.is_io = true and fd.type = ipv4")
    buffer_field = chisel.request_field("evt.buffer")
    fd_field = chisel.request_field("fd.num")
    pid_field = chisel.request_field("proc.pid")
    rawtime_field = chisel.request_field("evt.rawtime")
    buflen_field = chisel.request_field("evt.buflen.net")
    sysdig.set_snaplen(3000)
    return true
end

transactions = {}

function parse_request(req_buffer)
    method, url = string.match(req_buffer, "^(%u+) (%g+)")
    if method and url then
        return {
            method=method,
            url=url
        }
    end
    return nil
end

function parse_response(resp_buffer)
    resp_code = string.match(resp_buffer, "HTTP/[%g]+ (%d+)")
    if resp_code then
        return tonumber(resp_code)
    else
        return nil
    end
end

function on_event()
    buf = evt.field(buffer_field)

    if not buf then
        return
    end

    fd = evt.field(fd_field)
    pid = evt.field(pid_field)
    key = tostring(pid) + tostring(fd)
    timestamp = evt.field(rawtime_field)
    buflen = evt.field(buflen_field)
    transaction = transactions[key]
    if not transaction then
        request = parse_request(buf)
        if request then
            transactions[key] = {
                ts= timestamp,
                request= request,
                requestlen=buflen
            }
        end
    else
        response = parse_response(buf)
        if response then
            print(string.format("%s %s -> %d %d ms %d bytes",
                transaction["request"]["method"],
                transaction["request"]["url"],
                response,
                (timestamp - transaction["ts"])/1000000,
                transaction["requestlen"] + buflen
            ))
            transactions[key] = nil
        end
    end
end