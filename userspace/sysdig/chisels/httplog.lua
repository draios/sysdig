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
description = "Show a log of all HTTP requests";
short_description = "HTTP requests log";
category = "Application";
args = {}

require "http"

-- Initialization callback
function on_init()
    http_init()
    -- The -pc or -pcontainer options was supplied on the cmd line
    print_container = sysdig.is_print_container_data()

    return true
end

function on_transaction(transaction)
    if print_container then
        container = " " .. transaction["container"] .. " "
    else
        container = " "
    end
    print(string.format("%s%s%s method=%s url=%s response_code=%d latency=%dms size=%dB",
                evt.field(datetime_field),
                container,
                transaction["dir"],
                transaction["request"]["method"],
                transaction["request"]["url"],
                transaction["response"]["code"],
                (transaction["response"]["ts"] - transaction["request"]["ts"])/1000000,
                transaction["response"]["length"]
            ))
end

function on_event()
    run_http_parser(evt, on_transaction)
end
