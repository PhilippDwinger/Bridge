-- Live test against a real node and a Rust echo client (tests/e2e sdk-fixture, docs/10 §2.3).
-- Started by tests/run_tests.sh with BRIDGE_FIXTURE_INFO = the fixture's info line.
local process = require("@lune/process")
local Bridge4 = require("../src/Bridge4")
local Json = Bridge4.Json
local Enc = Bridge4.Enc

Bridge4.lune()
local info = Json.parse(process.env.BRIDGE_FIXTURE_INFO, 4096)

local function untilMessage(client: any, wanted: (any) -> boolean): any
	local deadline = os.clock() + 30
	while os.clock() < deadline do
		for _, message in client:receive(1).messages do
			if wanted(message) then
				return message
			end
		end
	end
	error("expected message did not arrive", 0)
end

local function equal(actual: any, expected: any, what: string)
	if actual ~= expected then
		error(what .. ": expected " .. tostring(expected) .. " got " .. tostring(actual), 0)
	end
end

local alice = Bridge4.Client.join(Bridge4.generateIdentity(), info.link)
equal(alice.net, info.net, "net")
local echo = alice:cardOf(info.echo)

local sent = alice:send(echo, "hallo aus Luau – äöü 😀")
local answer = untilMessage(alice, function(m)
	return m.from == info.echo
end)
equal(answer.content.text, "echo: hallo aus Luau – äöü 😀", "echo")
equal(Enc.b64(answer.content.reply), Enc.b64(sent), "reply")

local response = alice:request(echo, Json.object({ prompt = "Wie geht's?", max_tokens = 5 }), 30)
assert(response, "no response")
equal(Json.canonical(Json.parse(response.content.data, 1000)), '{"max_tokens":5,"prompt":"Wie geht\'s?"}', "task")

local key = Bridge4.generateIdentity()
local statement = alice:issueAgent(key:keyCard("client", "Luau-KI", 1), { to = { info.echo }, note = "Luau-KI" })
local agent = Bridge4.Client.new(key, info.url):withAgent(statement):connect()
agent:send(agent:cardOf(info.echo), "von agent")
local echoed = untilMessage(agent, function(m)
	return m.from == info.echo
end)
equal(echoed.content.text, "echo: von agent [agent of " .. alice.identity.id .. "]", "agent echo")
local ok, problem = pcall(function()
	agent:send(agent:cardOf(alice.identity.id), "an Alice")
end)
equal(ok, false, "agent outside of to")
equal(Bridge4.Errors.code(problem), "FORBIDDEN", "to")

alice:send(echo, "agent-hello")
local hello = untilMessage(alice, function(m)
	return m.from == info.echo_agent
end)
equal(hello.content.text, "hallo vom agent", "hello")
equal(hello.agentOf and hello.agentOf.owner, info.echo, "owner")
equal(hello.agentOf and hello.agentOf.note, "Echo-Agent", "note")

equal(alice:revokeAgent(key.id), true, "revoke")
local gone, why = pcall(function()
	agent:receive(0)
end)
equal(gone, false, "revoked agent still served")
equal(Bridge4.Errors.code(why), "NO_SESSION", "revoked")
print("live: passed")
