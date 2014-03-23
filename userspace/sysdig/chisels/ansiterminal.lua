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

for c, v in pairs(colors) do
    makecolor(c, v)
end

function ansiterminal.clearscreen()
    io.write(schar(27) .. '[' .. "2J")
end

function ansiterminal.goto(x, y)
    io.write(schar(27) .. '[' .. tostring(x) .. ";" .. tostring(y) .. 'H')
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

return ansiterminal
