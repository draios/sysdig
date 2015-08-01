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
description = "Show a \"tail\" of HTTP transactions";
short_description = "Tail of http transactions";
category = "Net";

-- Chisel argument list
args = {
    {
        name = "by",
        description = "Show top HTTP transactions by: ncalls, time or bytes, default is ncalls",
        argtype = "string",
        optional = true
    },
}


-- Initialization callback
function on_init()

    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    chisel.set_filter("evt.is_io = true and evt.buflen.net > 0 and fd.type = ipv4")
    buffer_field = chisel.request_field("evt.buffer")
    fd_field = chisel.request_field("fd.num")
    pid_field = chisel.request_field("proc.pid")
    rawtime_field = chisel.request_field("evt.rawtime")
    buflen_field = chisel.request_field("evt.buflen.net")
    datetime_field = chisel.request_field("evt.datetime")
    dir_field = chisel.request_field("evt.io_dir")

    if print_container then
        container_field = chisel.request_field("container.name")
    end

    sysdig.set_snaplen(1024)
    return true
end

islive = false
partial_transactions = {}

function parse_request(req_buffer)
    method, url = string.match(req_buffer, "^(%u+) (%g+)")
    if method and url then
        host = string.match(req_buffer, "Host: (%g+)%.%.")
        if host then
            url = host .. url
        end
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
    fd = evt.field(fd_field)
    pid = evt.field(pid_field)
    evt_dir = evt.field(dir_field)
    key = string.format("%d\001\001%d", pid, fd)

    timestamp = evt.field(rawtime_field)
    buflen = evt.field(buflen_field)

    transaction = partial_transactions[key]
    if not transaction then
        request = parse_request(buf)
        if request then
            transaction_dir = "<NA>"
            if evt_dir == "read" then
                transaction_dir = "<"
            elseif evt_dir == "write" then
                transaction_dir = ">"
            end
            partial_transactions[key] = {
                ts= timestamp,
                request= request,
                request_len=buflen,
                dir=transaction_dir
            }
            if print_container then
                partial_transactions[key]["container"] = evt.field(container_field)
            end
        end
    else
        response = parse_response(buf)
        if response then
            print(string.format("%s %s method=%s url=%s response_code=%d latency=%dms size=%dB",
                evt.field(datetime_field),
                transaction["dir"],
                transaction["request"]["method"],
                transaction["request"]["url"],
                response,
                (timestamp - transaction["ts"])/1000000,
                transaction["request_len"] + buflen
            ))
            partial_transactions[key] = nil
        end
    end
end