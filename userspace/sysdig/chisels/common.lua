--[[ 
A bunch of functions that are helpful in multiple scripts
]]--

--[[ 
Extends a string to newlen with spaces
]]--
function extend_string(s, newlen)
	ccs = "                                                                                                        "
	s = s .. string.sub(ccs, 0, newlen - string.len(s))
	return s
end

--[[ 
convert a number into a byte representation.
E.g. 1230 becomes 1.23K
]]--
function format_bytes(val)
	if val > (1024 * 1024 * 1024) then
		return string.format("%.2fP", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024) then
		return string.format("%.2fT", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024) then
		return string.format("%.2fG", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024) then
		return string.format("%.2fM", val / (1024 * 1024))
	elseif val > 1024 then
		return string.format("%.2fKB", val / (1024))
	else
		return string.format("%dB", val)
	end
end

--[[ 
convert a nanosecond time interval into a s.ns representation.
E.g. 1100000000 becomes 1.1s
]]--
function format_time_interval(val)
	return string.format("%u.%03us", val / 1000000000, (val % 1000000000) / 1000000)
end

--[[ 
extract the top num entries from the table t, after sorting them based on the entry value using the function order()
]]--
function pairs_top_by_val(t, num, order)
	local keys = {}
	for k in pairs(t) do keys[#keys+1] = k end

	table.sort(keys, function(a,b) return order(t, a, b) end)

	local i = 0
	return function()
		i = i + 1
		if (num == 0 or i <= num) and keys[i] then
			return keys[i], t[keys[i]]
		end
	end
end
