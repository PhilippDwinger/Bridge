--[[
	Every Luau script of the extension compiles (like Roblox does it when the script starts): catches what the type
	check does not - above all Luau's limit of 200 locals in one function (the main chunk of a big script).
	lune run test_compile.luau
]]
local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")

local failures = 0
local count = 0
local function walk(dir: string)
	for _, name in ipairs(fs.readDir(dir)) do
		local path = dir .. "/" .. name
		if fs.isDir(path) then
			walk(path)
		elseif string.sub(name, -5) == ".luau" then
			count += 1
			local ok, err = pcall(luau.compile, fs.readFile(path))
			if not ok then
				failures += 1
				print("  FAIL  " .. path .. ": " .. string.gsub(tostring(err), "%z", ""))
			end
		end
	end
end
walk("../src")
print(string.format("  %s  %d scripts compile%s", if failures == 0 then "OK  " else "FAIL", count,
	if failures == 0 then "" else " (" .. failures .. " do not)"))
process.exit(if failures == 0 then 0 else 1)
