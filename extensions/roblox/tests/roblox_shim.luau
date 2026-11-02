--[[
	Test only: the few Roblox APIs Bridge.luau uses, built on Lune (https://lune-org.github.io), so the real module
	can run outside Roblox against a real Bridge server. Load it before requiring the module:

	    local shim = require("./roblox_shim")
	    local Bridge = require("../src/Bridge")
]]
local net = require("@lune/net")
local serde = require("@lune/serde")
local luneTask = require("@lune/task")

local shim = {
	requests = 0,
	httpDisabled = false,
	closeHandlers = {},
	log = {},
}

-- Roblox globals
_G.task = luneTask
task = luneTask
warn = function(...)
	local parts = {}
	for i = 1, select("#", ...) do
		parts[i] = tostring(select(i, ...))
	end
	table.insert(shim.log, table.concat(parts, " "))
	if shim.printWarnings then
		print("  [warn]", table.concat(parts, " "))
	end
end

local HttpService = {}

-- Roblox encodes an empty table as [] - Lune's serde as {}; Bridge does not care here
function HttpService:JSONEncode(value)
	return serde.encode("json", value)
end

function HttpService:JSONDecode(text)
	return serde.decode("json", text)
end

local guidCounter = 0
function HttpService:GenerateGUID(braces)
	guidCounter += 1
	local hex = {}
	for i = 1, 32 do
		hex[i] = string.format("%x", math.random(0, 15))
	end
	local text = table.concat(hex)
	text = string.sub(text, 1, 8) .. "-" .. string.sub(text, 9, 12) .. "-" .. string.sub(text, 13, 16) .. "-"
		.. string.sub(text, 17, 20) .. "-" .. string.sub(text, 21, 32)
	return if braces == false then text else "{" .. text .. "}"
end

function HttpService:RequestAsync(request)
	if shim.httpDisabled then
		error("Http requests are not enabled. Enable via game settings", 2)
	end
	shim.requests += 1
	if shim.onRequest then
		shim.onRequest(request)
	end
	local ok, response = pcall(net.request, {
		url = request.Url,
		method = request.Method,
		headers = request.Headers,
		body = request.Body,
	})
	if not ok then
		error("HttpError: ConnectFail (" .. tostring(response) .. ")", 2)
	end
	return {
		Success = response.ok,
		StatusCode = response.statusCode,
		StatusMessage = response.statusMessage,
		Headers = response.headers,
		Body = response.body,
	}
end

local RunService = {}
function RunService:IsServer()
	return true
end
function RunService:IsStudio()
	return true
end

local services = { HttpService = HttpService, RunService = RunService }
shim.services = services -- tests can add more (Players, ServerStorage, ...)

game = {
	JobId = "",
	PlaceId = 0,
	GetService = function(_, name)
		local service = services[name]
		assert(service, "shim: service " .. tostring(name) .. " not available")
		return service
	end,
	BindToClose = function(_, callback)
		table.insert(shim.closeHandlers, callback)
	end,
}
_G.game = game

function shim.close()
	for _, callback in ipairs(shim.closeHandlers) do
		callback()
	end
end

return shim
