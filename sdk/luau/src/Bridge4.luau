--!strict
--[[
	Bridge 4 for Luau (docs/10 §2.5): Roblox game servers and Lune. Join a network, send and receive end-to-end
	encrypted, tasks, agents, connected networks - same formats and checks as the Rust core.

	Luau crypto: port of TweetNaCl + RFC code, checked only by test vectors - residual risk R1 (docs/02).

	Roblox: only on the server (HttpService must be enabled). Keep the key file text in ServerStorage or a DataStore,
	never in ReplicatedStorage. Better: make the key with bridge-node/BridgeControll (good randomness) and paste it.
]]

local Client = require("./Client")
local Crypto = require("./Crypto")
local Enc = require("./Enc")
local Errors = require("./Errors")
local Json = require("./Json")
local Platform = require("./Platform")
local Proto = require("./Proto")
local Random = require("./Random")

local Bridge4 = {
	Client = Client,
	Crypto = Crypto,
	Enc = Enc,
	Errors = Errors,
	Json = Json,
	Proto = Proto,
	Random = Random,
	identity = Proto.identity,
	identityFromKeyFile = Proto.identityFromKeyFile,
	generateIdentity = Proto.generateIdentity,
	parseStatement = Proto.parseStatement,
}

--- Lune (tests, tools): HTTP over @lune/net, time from @lune/datetime, randomness from the OS (/dev/urandom).
function Bridge4.lune()
	local net = (require :: any)("@lune/net")
	local process = (require :: any)("@lune/process")
	local DateTime = (require :: any)("@lune/datetime")
	Platform.http = function(method: string, url: string, headers: { [string]: string }, body: string?)
		local response = net.request({ url = url, method = method, headers = headers, body = body })
		return { status = response.statusCode, body = response.body }
	end
	Platform.nowMs = function(): number
		return DateTime.now().unixTimestampMillis
	end
	Random.setEntropySource(function(): string
		return process.spawn("head", { "-c", "64", "/dev/urandom" }).stdout
	end)
end

--- Roblox (server): HttpService:RequestAsync, DateTime, randomness from HttpService GUIDs mixed with the clock.
function Bridge4.roblox()
	local HttpService = (game :: any):GetService("HttpService")
	Platform.http = function(method: string, url: string, headers: { [string]: string }, body: string?)
		local response = HttpService:RequestAsync({ Url = url, Method = method, Headers = headers, Body = body })
		return { status = response.StatusCode, body = response.Body }
	end
	Platform.nowMs = function(): number
		return (DateTime :: any).now().UnixTimestampMillis
	end
	Random.setEntropySource(function(): string
		local parts = {}
		for _ = 1, 8 do
			table.insert(parts, HttpService:GenerateGUID(false))
		end
		table.insert(parts, tostring(os.clock()))
		table.insert(parts, tostring((DateTime :: any).now().UnixTimestampMillis))
		return Crypto.sha256(table.concat(parts)) .. Crypto.sha256(table.concat(parts, "|"))
	end)
end

return Bridge4
