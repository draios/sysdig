description = "Scavenges the files written by processes and saves them. Use it in live mode or against a trace file. The file name will be changed to include the container name and the original directory path. Combine this script with a filter to restrict what it saves.";
short_description = "Scavenges the files written by processes and saves them.";
category = "I/O";

args =
{
}

files = {}

function string.starts(string, start)
	return string.sub(string, 1, string.len(start)) == start
end

function on_init()
	fbuf = chisel.request_field("evt.rawarg.data")
	fres = chisel.request_field("evt.rawarg.res")
	fname = chisel.request_field("fd.name")
	fcontainername = chisel.request_field("container.name")
	
	sysdig.set_snaplen(16384)
	chisel.set_filter("evt.dir=< and evt.rawres>=0 and fd.type=file and (evt.is_open_write=true or evt.is_io_write=true or evt.type=close)")

	return true
end

function on_event()
	local buf = evt.field(fbuf)
	local res = evt.field(fres)
	local name = evt.field(fname)
	local containername = evt.field(fcontainername)
	local etype = evt.get_type()
	
	if etype == "open" then
		if string.starts(name, "/dev") or 
				string.starts(name, "/sys") or
				string.starts(name, "/tmp") or
				string.starts(name, "/run") or
				string.starts(name, "/proc") then
			return true
		end

		-- print("Detected open for file " .. name)
		files[name] = ""
	elseif etype == "close" then
		if files[name] then
			file_name = containername .. string.gsub(name, "/", "_")

			print("Scavenged file " .. name .. ", saving as " .. file_name)

			fp = io.output(file_name)
			f = files[name]
			io.write(f)
			io.close(fp)

			files[name] = nil
		end
	elseif etype == "write" then
		if files[name] then
			if res == string.len(buf) then
				-- print("Appending to file " .. name)
				f = files[name]
				files[name] = f .. buf
			else
				print("Ignoring file " .. name .. " because of snaplen: " .. res .. " vs " .. string.len(buf))
				files[name] = nil
			end
		end
	elseif etype ~= "writev" and etype ~= "pwrite" then
		print("Unknown event type " .. etype)
	end
	return true
end
