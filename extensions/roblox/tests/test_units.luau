-- Unit tests without a server: SHA-256, Base64, zlib inflate, URL normalising (vectors from Python: vectors.json)
local shim = require("./roblox_shim")
local fs = require("@lune/fs")
local serde = require("@lune/serde")
local Bridge = require("../src/Bridge")

local ok, fail = 0, 0
local function check(name, condition, info)
	if condition then ok += 1 else fail += 1; print("  FAIL  " .. name .. "  " .. tostring(info or "")) end
end

local cases = serde.decode("json", fs.readFile("vectors.json"))
local started = os.clock()
for index, case in ipairs(cases) do
	local text = Bridge.Base64Decode(case.text_b64)
	check("sha256 #" .. index, Bridge.Sha256(text) == case.sha256, Bridge.Sha256(text) .. " vs " .. case.sha256)
	local packed = Bridge.Base64Decode(case.zlib_b64)
	local good, unpacked = pcall(Bridge.Inflate, packed)
	check("inflate #" .. index .. " (level " .. case.level .. ", " .. #text .. " bytes)", good and unpacked == text, unpacked)
end
print(string.format("  %d vectors in %.2f s", #cases, os.clock() - started))
check("sha256('abc')", Bridge.Sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("inflate rejects garbage", not pcall(Bridge.Inflate, "not zlib at all"))
local n = Bridge.NormalizeServer
check("normalize: adds https, cuts /admin, drops :443", n(" Muttchen.tail91b057.ts.net:443/admin/ ") == "https://muttchen.tail91b057.ts.net", n(" Muttchen.tail91b057.ts.net:443/admin/ "))
check("normalize: keeps other ports", n("https://x.ts.net:10000") == "https://x.ts.net:10000")
check("normalize: keeps a sub path, cuts Bridge routes", n("https://host/bridge/server/status") == "https://host/bridge", n("https://host/bridge/server/status"))
check("ErrorId", Bridge.ErrorId("[Bridge] RECIPIENT_NOT_FOUND: nope (/message/send -> 404)") == "RECIPIENT_NOT_FOUND")
print(string.format("\n%d ok, %d failed", ok, fail))
if fail > 0 then
	require("@lune/process").exit(1)
end
