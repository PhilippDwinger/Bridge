--[[
	Live test of Bridge.luau against a REAL Bridge server (started by run_tests.py).
	Env: BRIDGE_URL, BRIDGE_ADMIN_PASSWORD
]]
local shim = require("./roblox_shim")
local net = require("@lune/net")
local serde = require("@lune/serde")
local process = require("@lune/process")
local Bridge = require("../src/Bridge")

local URL = process.env.BRIDGE_URL
local ADMIN = process.env.BRIDGE_ADMIN_PASSWORD
local results = { ok = 0, fail = 0 }

local function check(name, condition, info)
	if condition then
		results.ok += 1
		print("  OK    " .. name)
	else
		results.fail += 1
		print("  FAIL  " .. name .. "  " .. tostring(info or ""))
	end
end

local function waitFor(condition, seconds)
	local deadline = os.clock() + (seconds or 5)
	while os.clock() < deadline do
		if condition() then
			return true
		end
		task.wait(0.05)
	end
	return condition()
end

local function post(path, body)
	local response = net.request({ url = URL .. path, method = "POST", headers = { ["Content-Type"] = "application/json" },
		body = serde.encode("json", body) })
	return response.statusCode, serde.decode("json", response.body)
end

local function same(a, b)
	return serde.encode("json", a) == serde.encode("json", b)
end

local function main()
-- region connect
local errors = {}
local A = Bridge.new({ Server = URL .. "/admin", Name = "Game A" })
local B = Bridge.new({ Server = URL, Name = "Game B" })
A.ErrorOccurred:Connect(function(err) table.insert(errors, "A " .. tostring(err)) end)
B.ErrorOccurred:Connect(function(err) table.insert(errors, "B " .. tostring(err)) end)
local connectedA = nil
A.Connected:Connect(function(ip) connectedA = ip end)
check("two clients connect by themselves (AutoStart), /admin in the URL is cut off", A:WaitForConnection(10) and B:WaitForConnection(10)
	and A.Server == URL, A.Server)
check("Connected signal with the client IP", waitFor(function() return connectedA == A.ClientIp end, 2), connectedA)
check("both have different client IPs on this server", A.ClientIp ~= B.ClientIp
	and string.find(A.ClientIp, Bridge.ADDRESS_SPLIT, 1, true) ~= nil, A.ClientIp)
check("public realm and limits known", type(A.PublicRealm) == "string" and A.Limits.max_poll_messages == 100, A.PublicRealm)
-- endregion

-- region topics
local gotB, gotA = {}, {}
local subB = B:Subscribe(nil, "playersync", function(data, event)
	table.insert(gotB, { data = data, sender = event.SenderIp })
end)
A:Subscribe(nil, "playersync", function(data)
	table.insert(gotA, data)
end)
for tick = 1, 10 do
	A:Publish(nil, "playersync", { tick = tick, players = { { u = 1, x = tick } } })
end
check("10 snapshots of A arrive at B, in order, with the sender IP", waitFor(function() return #gotB == 10 end, 5)
	and gotB[10].data.tick == 10 and gotB[1].sender == A.ClientIp, #gotB)
task.wait(0.5)
check("A does not get its own snapshots back", #gotA == 0, #gotA)
A:Publish(nil, "playersync", { tick = 99 }, { IncludeSelf = true })
task.wait(0.8)
check("IncludeSelf: even then A's handler does not see its own event (IgnoreOwnEvents)", #gotA == 0, #gotA)

local before = B:GetStats().Requests
table.clear(gotB)
for tick = 1, 30 do
	task.spawn(function() A:Publish(nil, "playersync", { tick = tick }) end)
end
waitFor(function() return #gotB >= 30 end, 8)
local used = B:GetStats().Requests - before
check("30 events reach B with only a few poll requests (batch poll)", #gotB == 30 and used <= 12, string.format("%d events, %d requests", #gotB, used))
-- endregion

-- region PublishLatest + Subscribe Latest (only the newest state counts)
check("server allows publishes inside a poll (limits.max_poll_publishes)", A.Limits.max_poll_publishes == 10, A.Limits.max_poll_publishes)
local function increasing(list)
	for index = 2, #list do
		if list[index] <= list[index - 1] then
			return false
		end
	end
	return true
end
local allB, newestB = {}, {}
local subAll = B:Subscribe(nil, "pos", function(data) table.insert(allB, data.n) end)
local subNewest = B:Subscribe(nil, "pos", function(data) table.insert(newestB, data.n) end, { Latest = true })
task.wait(0.3)
for n = 1, 20 do
	A:Publish(nil, "pos", { n = n })
end
waitFor(function() return #allB >= 20 end, 5)
task.wait(0.3)
check("Subscribe: a normal handler gets all 20 events", #allB == 20 and increasing(allB), #allB)
check("Subscribe Latest: only the newest of each poll (fewer, in order, ends with 20)",
	#newestB < 20 and #newestB >= 1 and newestB[#newestB] == 20 and increasing(newestB), table.concat(newestB, ","))
subAll:Disconnect()

-- both stream their state 30 times per second for 2 s: values go out with the polls, old ones are replaced
local newestA = {}
local subA = A:Subscribe(nil, "pos", function(data) table.insert(newestA, data.n) end, { Latest = true })
table.clear(newestB)
task.wait(0.5)
local requestsA, requestsB = A:GetStats().Requests, B:GetStats().Requests
local started = os.clock()
local n = 0
while os.clock() - started < 2 do
	n += 1
	A:PublishLatest(nil, "pos", { n = n })
	B:PublishLatest(nil, "pos", { n = n })
	task.wait(1 / 30)
end
local streamed = n
task.wait(0.8)
requestsA, requestsB = A:GetStats().Requests - requestsA, B:GetStats().Requests - requestsB
check("PublishLatest: the newest value arrives on both sides", newestA[#newestA] == streamed and newestB[#newestB] == streamed,
	tostring(newestA[#newestA]) .. "/" .. tostring(newestB[#newestB]) .. " of " .. streamed)
check("PublishLatest: never an older value after a newer one", increasing(newestA) and increasing(newestB))
check("PublishLatest: only the newest went out (fewer values than published)", #newestB < streamed * 0.6, #newestB .. " of " .. streamed)
check("PublishLatest: sending + receiving in about one request per PollInterval (publish inside the poll)",
	requestsA <= 2.8 / A.PollInterval + 3 and requestsB <= 2.8 / B.PollInterval + 3 and not A._noPiggyback,
	string.format("A %d, B %d requests in 2.8 s", requestsA, requestsB))
check("PublishLatest: about 4 values per second arrive (PollInterval 0.25)", #newestB >= 6, #newestB)

-- an older Bridge server ignores "publish" in a poll: the client notices it and sends separately
local original = Bridge.Client._request
A._request = function(self, path, body, options)
	if type(body) == "table" then
		body.publish = nil
	end
	return original(self, path, body, options)
end
table.clear(newestB)
started = os.clock()
while os.clock() - started < 1.5 do
	n += 1
	A:PublishLatest(nil, "pos", { n = n })
	B:PublishLatest(nil, "pos", { n = n })
	task.wait(1 / 30)
end
task.wait(1)
check("older server: values still arrive (separately), the newest last", A._noPiggyback and newestB[#newestB] == n
	and increasing(newestB), tostring(newestB[#newestB]) .. " / " .. n)
A._request = nil
A._noPiggyback = false
A.Limits.max_poll_publishes = nil
table.clear(newestB)
A:PublishLatest(nil, "pos", { n = n + 1 })
check("without poll publishes (Limits) PublishLatest sends on its own", waitFor(function() return newestB[#newestB] == n + 1 end, 3),
	newestB[#newestB])
A.Limits.max_poll_publishes = 10
local ok, err = pcall(A.PublishLatest, A, nil, "pos", nil)
check("PublishLatest without data -> error", not ok and string.find(tostring(err), "nil", 1, true) ~= nil, err)
ok, err = pcall(A.PublishLatest, A, nil, "pos", { f = function() end })
check("PublishLatest with data that is no JSON -> error at once (never inside a poll)", not ok
	and string.find(tostring(err), "ARGUMENT_ERROR", 1, true) ~= nil and next(A._latest) == nil, err)
subA:Disconnect()
subNewest:Disconnect()
-- endregion

-- region direct messages
local inbox = {}
B.MessageReceived:Connect(function(message) table.insert(inbox, message) end)
local replies = {}
A.MessageReceived:Connect(function(message) table.insert(replies, message) end)
A:Send(B.ClientIp, { hello = "welt" })
check("direct message (auto -> fast) arrives", waitFor(function() return #inbox == 1 end) and inbox[1].Content.hello == "welt"
	and inbox[1].SenderIp == A.ClientIp and inbox[1].Mode == "fast", inbox[1] and inbox[1].Mode)
if inbox[1] then
	inbox[1]:Reply({ thanks = true })
end
check("Reply arrives at A in the same conversation", waitFor(function() return #replies == 1 end)
	and replies[1].Content.thanks == true and replies[1].ConversationId == inbox[1].ConversationId, #replies)

local big = { rows = {} }
for i = 1, 1500 do
	big.rows[i] = { id = i, name = "Spieler " .. i .. " äöü 🚀", pos = { i * 0.5, 3, -i } }
end
table.clear(inbox)
A:Send(B.ClientIp, big, { Mode = "safe" })
check("safe message (" .. math.floor(#serde.encode("json", big) / 1024) .. " KiB, chunks + SHA-256) arrives exactly",
	waitFor(function() return #inbox == 1 end, 15) and same(inbox[1].Content, big) and inbox[1].Mode == "safe", #inbox)
table.clear(inbox)
A:Send(B.ClientIp, big, { Mode = "compressed" })
check("compressed message (zlib + Base64, inflated in Luau) arrives exactly",
	waitFor(function() return #inbox == 1 end, 15) and same(inbox[1].Content, big) and inbox[1].Mode == "compressed", #inbox)
local huge = { rows = {} }
for i = 1, 4000 do
	huge.rows[i] = { id = i, name = "Spieler " .. i, pos = { i * 0.5, 3, -i } }
end
table.clear(inbox)
A:Send(B.ClientIp, huge)
check("auto mode: content over the fast limit goes as safe by itself", waitFor(function() return #inbox == 1 end, 20)
	and inbox[1].Mode == "safe" and same(inbox[1].Content, huge), inbox[1] and inbox[1].Mode)
local ok, err = pcall(A.Send, A, A.ServerUrl .. Bridge.ADDRESS_SPLIT .. "doesnotexist", { x = 1 })
check("errors are readable text with the ID", not ok and Bridge.ErrorId(err) == "RECIPIENT_NOT_FOUND", err)
-- endregion

-- region commands
B:HostCommand(nil, "add", function(args) return args.a + args.b end, { Description = "adds two numbers" })
B:HostCommand(nil, "boom", function() error("kaputt") end)
B:HostCommand(nil, "slow", function(args) task.wait(args.seconds) return "done" end)
check("Call returns the answer of the host", A:Call("add", { a = 2, b = 3 }) == 5)
ok, err = pcall(A.Call, A, "boom", {})
check("an error in the host's handler -> Call throws COMMAND_FAILED with the text", not ok
	and Bridge.ErrorId(err) == "COMMAND_FAILED" and string.find(err, "kaputt", 1, true) ~= nil, err)
local t0 = os.clock()
check("answer later than the server wait: Call gets it from the poll loop", A:Call("slow", { seconds = 1.5 },
	{ ServerWait = 0.3, Timeout = 10 }) == "done" and os.clock() - t0 > 1.2, os.clock() - t0)
ok, err = pcall(A.Call, A, "slow", { seconds = 3 }, { ServerWait = 0.2, Timeout = 1 })
check("Timeout -> TIMEOUT", not ok and Bridge.ErrorId(err) == "TIMEOUT", err)
local async = {}
A.ResponseReceived:Connect(function(response) table.insert(async, response) end)
task.wait(2.5) -- the late answer of the timed out call comes as ResponseReceived
table.clear(async)
local taskId = A:Call("add", { a = 10, b = 5 }, { Async = true })
check("Async call: answer comes as ResponseReceived", waitFor(function() return #async >= 1 end, 5)
	and async[1].TaskId == taskId and async[1].Content == 15, async[1] and async[1].Content)
local commands = A:GetCommands(nil)
check("GetCommands shows B's commands", type(commands) == "table" and commands.add ~= nil, commands)
-- endregion

-- region sessions
local tokenBefore = A._token
A._tokenExpires = os.time() + 60 -- inside the margin: renewed before the next request
A:GetMe()
check("session is renewed before it runs out", A._token ~= tokenBefore and A._token ~= nil)
post("/client/logout", { session_token = A._token })
local me = A:GetMe()
check("SESSION_INVALID -> logs in again by itself", me.client_ip == A.ClientIp, me.client_ip)
-- endregion

-- region stable identity
local secret = "test-identity-secret-0123456789-abcdef"
local C = Bridge.new({ Server = URL, Name = "Game C", IdentitySecret = secret })
check("identity client connects", C:WaitForConnection(10), C.State)
local ipC = C.ClientIp
C:Destroy()
local C2 = Bridge.new({ Server = URL, Name = "Game C", IdentitySecret = secret })
check("same IdentitySecret -> same client IP again (login, no new client)", C2:WaitForConnection(10) and C2.ClientIp == ipC, C2.ClientIp)
-- endregion

-- region wishes before the connection is there
local F = Bridge.new({ Server = URL, Name = "Game F", AutoStart = false, ConnectTimeout = 0 })
local gotF = {}
local early = F:Subscribe(nil, "playersync", function(data) table.insert(gotF, data) end)
check("Subscribe before the connection: no error, done as soon as connected", early ~= nil and F.State ~= "connected", F.State)
F.ConnectTimeout = 30
F:WaitForConnection(10)
A:Publish(nil, "playersync", { tick = 555 })
check("... and the event arrives", waitFor(function() return #gotF > 0 and gotF[#gotF].tick == 555 end, 5), #gotF)
F:Destroy()
-- endregion

-- region Bridge restart without data (admin reset)
local oldA, oldB, oldRealm = A.ClientIp, B.ClientIp, A.PublicRealm
local changed = {}
A.ClientIpChanged:Connect(function(new, old) table.insert(changed, { new, old }) end)
local status = post("/admin/reset", { password = ADMIN })
check("server reset (like a restart without backup)", status == 200, status)
table.clear(gotB)
-- the next request of A runs into SESSION_INVALID -> login fails -> registers again -> restores its topics
local published = pcall(A.Publish, A, nil, "playersync", { tick = 1000 })
check("A: re-registered by itself, new IP, ClientIpChanged fired", published and A.ClientIp ~= oldA and #changed == 1
	and changed[1][2] == oldA, A.ClientIp)
check("the public realm got a new address and is used", A.PublicRealm ~= nil and A.PublicRealm ~= oldRealm, A.PublicRealm)
check("B (only polling) also came back by itself", waitFor(function() return B.ClientIp ~= oldB and B.State == "connected" end, 15), B.State)
waitFor(function() return #gotB > 0 end, 3)
for tick = 1001, 1003 do
	A:Publish(nil, "playersync", { tick = tick })
end
check("after the restart B's subscription works again (restored)", waitFor(function()
	return #gotB > 0 and gotB[#gotB].data.tick == 1003
end, 8), #gotB)
check("A's hosted commands came back on B's side too", A:Call("add", { a = 1, b = 1 }) == 2)
check("identity client: same IP after the reset", (pcall(C2.GetMe, C2)) and C2.ClientIp == ipC, C2.ClientIp)
-- endregion

-- region unsubscribe, destroy
subB:Disconnect()
task.wait(0.3)
local res = A:Publish(nil, "playersync", { tick = 2000 })
check("Disconnect of the last handler unsubscribes on the server (nobody but A left -> 0 receivers)", res.subscribers == 0, res.subscribers)
local lastIp, lastPassword = A.ClientIp, A._password
local bye = false
A:BindToClose(function()
	A:Publish(nil, "playersync", { bye = true })
	bye = true
end)
A:Destroy()
local code = post("/client/login", { client_ip = lastIp, password = lastPassword })
check("Destroy: BindToClose ran first, the ephemeral client is deleted on the server", bye and code == 401, code)
ok, err = pcall(A.Send, A, B.ClientIp, 1)
check("a destroyed client throws DESTROYED", not ok and Bridge.ErrorId(err) == "DESTROYED", err)
-- endregion

-- region setup problems
shim.httpDisabled = true
local D = Bridge.new({ Server = URL, Name = "no http" })
ok, err = pcall(D.Connect, D, 3)
check("HTTP off -> clear error HTTP_DISABLED (no endless retry)", not ok and Bridge.ErrorId(err) == "HTTP_DISABLED"
	and D.State == "failed", err)
shim.httpDisabled = false
D:Destroy()
local E = Bridge.new({ Server = "http://127.0.0.1:1", Name = "nobody there" })
t0 = os.clock()
ok, err = pcall(E.Connect, E, 2)
check("server unreachable -> NOT_CONNECTED after the timeout (keeps trying in the background)", not ok
	and Bridge.ErrorId(err) == "NOT_CONNECTED" and os.clock() - t0 < 4, err)
E:Destroy()
-- endregion

-- region request budget
Bridge.SetRequestBudget(60, 2)
task.wait(0.1)
t0 = os.clock()
for _ = 1, 5 do
	B:GetMe()
end
local took = os.clock() - t0
check("request budget: 60/min with burst 2 -> 5 requests take ~3 s", took > 2.0, took)
Bridge.SetRequestBudget(400)
-- endregion

-- region shutdown
shim.close()
check("game shutdown (BindToClose) destroys every client", #Bridge.GetClients() == 0 and B.State == "destroyed", #Bridge.GetClients())

local unexpected = {}
for _, text in ipairs(errors) do
	-- expected along the way: the reset, the deleted test recipient, the timed out call's late answer
	if not (string.find(text, "SESSION_INVALID") or string.find(text, "INVALID_CREDENTIALS") or string.find(text, "DESTROYED")
		or string.find(text, "CLIENT_NOT_FOUND")) then
		table.insert(unexpected, text)
	end
end
check("no unexpected background errors", #unexpected == 0, table.concat(unexpected, " | "))
-- endregion
end

local ran, crash = pcall(main)
if not ran then
	results.fail += 1
	print("  CRASH " .. tostring(crash))
end
print(string.format("\n%d ok, %d failed", results.ok, results.fail))
process.exit(if results.fail > 0 then 1 else 0)
