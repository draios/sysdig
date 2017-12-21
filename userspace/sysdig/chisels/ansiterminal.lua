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

local pairs = pairs
local tostring = tostring
local setmetatable = setmetatable
local schar = string.char

local ansiterminal = {}

local colors = {
    -- attributes
    reset = 0,
    clear = 0,
    bright = 1,
    dim = 2,
    underscore = 4,
    blink = 5,
    reverse = 7,
    hidden = 8,

    -- foreground
    black = 30,
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    white = 37,

    -- background
    onblack = 40,
    onred = 41,
    ongreen = 42,
    onyellow = 43,
    onblue = 44,
    onmagenta = 45,
    oncyan = 46,
    onwhite = 47,
}

local function makecolor(name, value)
	ansiterminal[name] = schar(27) .. '[' .. tostring(value) .. 'm'
end

function ansiterminal.enable_color(enable_colors)
    if enable_colors == true then
        for c, v in pairs(colors) do
            makecolor(c, v)
        end
    else
        for name, v in pairs(colors) do
            ansiterminal[name] = ""
        end
    end
end

function ansiterminal.clearscreen()
    io.write(schar(27) .. '[' .. "2J")
end

function ansiterminal.moveto(x, y)
    io.write(schar(27) .. '[' .. tostring(x) .. ";" .. tostring(y) .. 'H')
end

function ansiterminal.moveup(n)
    io.write(schar(27) .. '[' .. tostring(n) .. 'F')
end

function ansiterminal.clearline()
    io.write(schar(27) .. '[' .. "2K")
end

function ansiterminal.hidecursor()
    io.write(schar(27) .. '[' .. "?25l")
end

function ansiterminal.showcursor()
    io.write(schar(27) .. '[' .. "?25h")
end

function ansiterminal.setfgcol(color)
    io.write(schar(27) .. '[' .. "38;5;" .. color .. "m")
end

function ansiterminal.setbgcol(color)
    io.write(schar(27) .. '[' .. "48;5;" .. color .. "m")
end

return ansiterminal
