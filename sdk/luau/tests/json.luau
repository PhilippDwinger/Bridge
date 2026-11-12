local Json = require("../src/Json")
local fs = require("@lune/fs")
local V = Json.parse(fs.readFile("../vectors/vectors.json"), 4194304)
local failed = 0
for _, c in V.json.canonical do
	local ok, out = pcall(function()
		return Json.canonical(Json.parse(c["in"], 1048576))
	end)
	if not ok or out ~= c.out then
		failed += 1
		print("FAIL canonical", c["in"], ok, out)
	end
end
for _, text in V.json.invalid do
	if pcall(Json.parse, text, 1048576) then
		failed += 1
		print("FAIL accepted", text)
	end
end
print(failed == 0 and "json: all passed" or ("json: " .. failed .. " failed"))
