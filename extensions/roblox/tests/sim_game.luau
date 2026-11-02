--[[
	Load test: one simulated Roblox game server with PlayerSync's traffic pattern (3 snapshots per second with
	moving players, subscribed to the others). Start it twice (game A + B, own processes = own request budget):

	    lune run sim_game.luau <BridgeURL> <label> <seconds> [players]

	Prints requests per minute (Roblox allows 500), received snapshots per second and the delay.
]]
local shim = require("./roblox_shim")
local process = require("@lune/process")
local datetime = require("@lune/datetime")
local Bridge = require("../src/Bridge")

local url, label, seconds, playerCount = process.args[1], process.args[2], tonumber(process.args[3]) or 30,
	tonumber(process.args[4]) or 8
local SEND_RATE = 3

local function nowMs()
	return datetime.now().unixTimestampMillis
end

local client = Bridge.new({ Server = url, Name = "sim " .. label })
assert(client:WaitForConnection(15), "no connection")

local received, delays, senders = 0, {}, {}
client:Subscribe(nil, "playersync", function(data, event)
	received += 1
	senders[event.SenderIp] = true
	if data.sentAt then
		table.insert(delays, nowMs() - data.sentAt)
	end
end)

local requestsBefore = shim.requests
local started = os.clock()
local tick = 0
while os.clock() - started < seconds do
	task.wait(1 / SEND_RATE)
	tick += 1
	local players = {}
	for i = 1, playerCount do
		local angle = tick * 0.1 + i
		players[i] = { u = i, n = "Player" .. i, d = "Player" .. i, p = { math.cos(angle) * 20, 3, math.sin(angle) * 20 },
			r = angle, s = 16, a = false }
	end
	local ok, err = pcall(client.Publish, client, nil, "playersync", { v = 1, label = label, players = players, sentAt = nowMs() })
	if not ok then
		print("publish failed: " .. tostring(err))
	end
end
local elapsed = os.clock() - started
local requests = shim.requests - requestsBefore
table.sort(delays)
local function percentile(p)
	return if #delays > 0 then delays[math.max(1, math.ceil(#delays * p))] else -1
end
local count = 0
for _ in pairs(senders) do
	count += 1
end
print(string.format("RESULT %s: %.0f requests/min (limit 500), %.1f snapshots/s received from %d other server(s), delay median %d ms, p95 %d ms",
	label, requests / elapsed * 60, received / elapsed, count, percentile(0.5), percentile(0.95)))
client:Destroy()
process.exit(0)
