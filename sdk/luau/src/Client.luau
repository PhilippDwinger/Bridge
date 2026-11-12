--!strict
--[[
	The client of one node (docs/04 §7, docs/06 §7, docs/10): join, log in, cards, send, receive, acknowledge, tasks,
	agents, connected networks. Zero Trust from the client side: the node's card and its signed `info` are checked,
	every envelope is verified with the sender's (self-certifying) card and opened here, duplicates are dropped,
	answers are size-limited and parsed strictly. Runs only on the server (Roblox HttpService).
]]

local Enc = require("./Enc")
local Errors = require("./Errors")
local Json = require("./Json")
local Platform = require("./Platform")
local Proto = require("./Proto")

local MAX_ANSWER_BYTES = 4 * 1024 * 1024
local SEEN_MEMORY = 20000
local HOME_LIFETIME_MS = 30 * 24 * 3600 * 1000 - 60000

local Client = {}
Client.__index = Client

export type Received = { id: string, from: string, net: string, content: Proto.Content, agentOf: { owner: string, note: string? }? }
export type Inbox = { messages: { Received }, rejected: number, duplicates: number, warning: string? }

local function now(): number
	return Platform.nowMs()
end

--- A client of the node at `url` (`expectedNode`: its ID, if known - pinned).
function Client.new(identity: Proto.Identity, url: string, expectedNode: string?)
	url = (string.gsub(url, "/+$", ""))
	if string.sub(url, 1, 7) ~= "http://" and string.sub(url, 1, 8) ~= "https://" then
		Errors.format("node URL must start with http(s)://")
	end
	local self = setmetatable({}, Client)
	self.identity = identity
	self.url = url
	self.expectedNode = expectedNode
	self.card = identity:keyCard("client", nil, now())
	self.node = nil :: Proto.KeyCard?
	self.net = nil :: string?
	self.session = nil :: string?
	self.agent = nil :: Proto.Statement?
	self.ttlS = 7 * 24 * 3600
	self.maxPowTries = 2 ^ 26
	self.seen = {} :: { [string]: number }
	self.seenOrder = {} :: { string }
	self.pendingAcks = {} :: { { string } }
	self.stash = {} :: { Received }
	return self
end

function Client:_call(method: string, path: string, body: string?, withSession: boolean?): { [string]: any }
	local http = Platform.http
	if http == nil then
		Errors.raise("NO_PLATFORM", "call Bridge4.lune() or Bridge4.roblox() first")
	end
	local headers = { ["Content-Type"] = "application/json" }
	if withSession and self.session then
		headers["Authorization"] = "Bearer " .. self.session
	end
	local ok, response = pcall(http :: Platform.Http, method, self.url .. path, headers, body)
	if not ok then
		Errors.raise("UNAVAILABLE", "node not reachable: " .. tostring(response))
	end
	if #response.body > MAX_ANSWER_BYTES then
		Errors.untrusted("answer too large")
	end
	local parsed, answer = pcall(Json.parse, response.body, MAX_ANSWER_BYTES)
	if not parsed or not Json.isObject(answer) then
		Errors.untrusted("bad answer (" .. response.status .. ")")
	end
	if response.status ~= 200 then
		local retry = if type(answer.retry_after) == "number" then answer.retry_after else nil
		error(Errors.new(tostring(answer.error or ""), tostring(answer.message or ""), retry, response.status), 0)
	end
	return answer
end

function Client:_post(path: string, value: any, withSession: boolean?): { [string]: any }
	return self:_call("POST", path, if type(value) == "string" then value else Json.canonical(value), withSession)
end

function Client:_fetchInfo(): Proto.KeyCard
	local info = self:_call("GET", "/v4/info")
	local card = Proto.cardFromValue(info.card)
	if self.expectedNode ~= nil and card.id ~= self.expectedNode then
		Errors.untrusted("node ID does not match")
	end
	local statement = Proto.statementFromValue(info.info)
	Proto.verifyStatement(statement, { card }, 1)
	Proto.checkTime(statement, now())
	if statement.kind ~= "info" then
		Errors.untrusted("info statement expected")
	end
	self.node = card
	self.net = statement.net
	return card
end

function Client:_solve(challenge: { [string]: any }, node: Proto.KeyCard, body: { [string]: any })
	if challenge.pow ~= nil and challenge.pow ~= Json.null then
		body.pow = Enc.b64(Proto.solvePuzzle(challenge.pow, node, self.maxPowTries))
	end
end

--- Checks the node, then logs in (proof of work if asked; `home`, or the agent statement for an agent).
function Client:connect()
	local node = self:_fetchInfo()
	local challenge = self:_post("/v4/auth/challenge", Json.object())
	local body = Json.object({ challenge = challenge.challenge, card = self.card.raw })
	self:_solve(challenge, node, body)
	if self.agent then
		body.agent = self.agent.raw
	elseif self.net ~= node.id then
		local t = now()
		body.home = Proto.signStatement("home", self.net, t, t + HOME_LIFETIME_MS, Json.object({ node = node.id }), self.identity).raw
	end
	local login = Proto.signRequest(self.identity, node.id, "login", body, now())
	local answer = self:_post("/v4/auth/login", Json.canonical(login.raw))
	if type(answer.session) ~= "string" or #answer.session ~= 43 then
		Errors.untrusted("bad session token")
	end
	self.session = answer.session
	return self
end

--- Joins with a join link: checks the gateway (info, genesis, log), proof of work, invite code, membership.
function Client.join(identity: Proto.Identity, link: string)
	local parsed = Proto.parseLink(link)
	local self = Client.new(identity, parsed.gateway, parsed.node)
	local node = self:_fetchInfo()
	if self.net ~= parsed.net then
		Errors.untrusted("the gateway belongs to another network")
	end
	local entries = {}
	local position = 0
	while position < 4096 do
		local page = self:_post("/v4/net/" .. parsed.net .. "/log", Json.object({ from = position, max = 256 }))
		local listed = page.entries
		if not Json.isArray(listed) or #listed == 0 or #listed > 256 then
			break
		end
		for _, item in listed do
			position += 1
			local ok, statement = pcall(function()
				return Proto.parseStatement(Enc.b64Var(item, "entry", 65536))
			end)
			if ok then
				table.insert(entries, statement)
			elseif position == 1 then
				Errors.untrusted("network log: entry 0 is not a statement")
			end
		end
		if type(page.size) == "number" and position >= page.size then
			break
		end
	end
	Proto.gatewayInLog(parsed.net, node.id, entries)
	local challenge = self:_post("/v4/auth/challenge", Json.object({ ["for"] = "join" }))
	local body = Json.object({ challenge = challenge.challenge, card = self.card.raw })
	if parsed.code then
		body.code = parsed.code
	end
	self:_solve(challenge, node, body)
	local request = Proto.signRequest(identity, node.id, "join", body, now())
	local answer = self:_post("/v4/net/join", Json.canonical(request.raw))
	if answer.member ~= nil and answer.member ~= Json.null then
		local statement = Proto.statementFromValue(answer.member)
		Proto.verifyStatement(statement, { node }, 1)
		if statement.kind ~= "member" or statement.net ~= parsed.net or statement.body.member ~= identity.id then
			Errors.untrusted("the gateway answered with another membership")
		end
	end
	self.expectedNode = node.id
	return self:connect()
end

--- Logs in as an agent from now on (docs/10 §3); uses the agent card of the statement as its own card.
function Client:withAgent(statement: Proto.Statement)
	local agent = Proto.agentFromBody(statement.body)
	if agent.card.id ~= self.identity.id or agent.card.sign ~= self.identity.signPublic or agent.card.box ~= self.identity.boxPublic then
		Errors.untrusted("the agent statement is for another key")
	end
	self.card = agent.card
	self.agent = statement
	return self
end

--- Issues an agent card as this client (the owner, a member), homed at this client's node.
function Client:issueAgent(agentCard: Proto.KeyCard, options: { send: boolean?, receive: boolean?, to: { string }?, rate: number?, note: string?, days: number? }?): Proto.Statement
	local o = options or {}
	if self.net == nil or self.node == nil then
		Errors.untrusted("not connected")
	end
	local scopes = {}
	if o.receive ~= false then
		table.insert(scopes, "receive")
	end
	if o.send ~= false then
		table.insert(scopes, "send")
	end
	local agent: Proto.Agent = {
		agent = agentCard.id,
		card = agentCard,
		owner = self.card,
		node = (self.node :: Proto.KeyCard).id,
		scopes = scopes,
		to = o.to,
		rate = o.rate or 60,
		note = o.note,
	}
	local days = o.days or 7
	if days < 1 or days > 30 then
		Errors.format("agent: 1..=30 days")
	end
	local t = now()
	return Proto.signStatement("agent", self.net, t, t + days * 24 * 3600 * 1000, Proto.agentBody(agent), self.identity)
end

function Client:revokeAgent(agentId: string): boolean
	local request = Proto.signRequest(self.identity, self:_nodeId(), "agent-revoke", Json.object({ agent = agentId }), now())
	return self:_post("/v4/agent/revoke", Json.canonical(request.raw), true).ended == true
end

function Client:_nodeId(): string
	if self.node == nil then
		Errors.untrusted("not connected")
	end
	return (self.node :: Proto.KeyCard).id
end

--- The card of `id` - in the connected network `net`, if given (docs/10 §6).
function Client:cardOf(id: string, net: string?): Proto.KeyCard
	local body = Json.object({ id = Proto.checkId(id) })
	if net and net ~= self.net then
		body.net = Proto.checkId(net)
	end
	local card = Proto.cardFromValue(self:_post("/v4/card", body, true).card)
	if card.id ~= id then
		Errors.untrusted("node returned a card for another ID")
	end
	return card
end

--- Encrypts `content` (text, or a Content table) for `to`; `net`: a connected network. Returns the envelope ID.
function Client:send(to: Proto.KeyCard, content: any, net: string?): string
	if self.net == nil then
		Errors.untrusted("not connected")
	end
	if type(content) == "string" then
		content = { kind = "direct", ctype = "text/plain", text = content }
	end
	local dnet = if net and net ~= self.net then net else nil
	local envelope = Proto.seal(self.identity, self.net, to, Proto.contentBytes(content), now(), self.ttlS, dnet)
	self:_post("/v4/send", Json.canonical(envelope.raw), true)
	return envelope.id
end

--- Sends a task (application/json) and waits up to `waitS` seconds for its response; other messages are kept.
function Client:request(to: Proto.KeyCard, value: any, waitS: number?, net: string?): Received?
	local task = self:send(to, { kind = "task", ctype = "application/json", data = Json.canonical(value) }, net)
	local deadline = now() + (waitS or 30) * 1000
	while now() < deadline do
		local kept = self.stash
		self.stash = {}
		local inbox = self:receive(math.clamp(math.floor((deadline - now()) / 1000), 1, 20))
		for _, message in self.stash do
			table.insert(kept, message)
		end
		self.stash = kept
		local found: Received? = nil
		for _, message in inbox.messages do
			if found == nil and message.from == to.id and message.content.kind == "response" and message.content.reply == task then
				found = message
			elseif #self.stash < 1000 then
				table.insert(self.stash, message)
			end
		end
		if found then
			return found
		end
	end
	return nil
end

function Client:_connectedNets(answer: { [string]: any }): { string }
	local out = {}
	if not Json.isObject(answer.feds) or answer.master == nil or self.net == nil then
		return out
	end
	local ok, master = pcall(Proto.cardFromValue, answer.master)
	if not ok or master.id ~= self.net or master.role ~= "net" then
		return out
	end
	for peer, statement in answer.feds do
		if #out < 32 and Proto.checkFederation(statement, self.net, master, peer, now()) then
			table.insert(out, peer)
		end
	end
	return out
end

function Client:_open(value: any, cards: { [string]: any }, agents: { [string]: any }, connected: { string }): Received?
	local ok, result = pcall(function()
		local envelope = Proto.envelopeFromValue(value)
		local fromHere = envelope.net == self.net and envelope.dnet == nil
		local fromConnected = envelope.dnet == self.net and table.find(connected, envelope.net) ~= nil
		if envelope.to ~= self.identity.id or not (fromHere or fromConnected) then
			return nil
		end
		local card = Proto.cardFromValue(cards[envelope.from])
		if card.id ~= envelope.from then
			return nil
		end
		Proto.checkEnvelopeTime(envelope, now())
		local content = Proto.parseContent(Proto.open(envelope, self.identity, card))
		local agentOf = nil
		if agents[envelope.from] ~= nil then
			local checked, agent = pcall(function()
				return Proto.checkAgent(Proto.statementFromValue(agents[envelope.from]), envelope.net, now())
			end)
			if checked and agent.agent == card.id and Proto.cardText(agent.card) == Proto.cardText(card) then
				agentOf = { owner = agent.owner.id, note = agent.note }
			end
		end
		return { id = envelope.id, from = envelope.from, net = envelope.net, content = content, agentOf = agentOf }
	end)
	return if ok then result else nil
end

--- Fetches, verifies, opens; drops duplicates; acknowledges (repeated next time if that fails).
function Client:receive(waitS: number?): Inbox
	if #self.stash > 0 then
		local messages = self.stash
		self.stash = {}
		return { messages = messages, rejected = 0, duplicates = 0 }
	end
	local answer = self:_post("/v4/poll", Json.object({ wait = math.clamp(math.floor(waitS or 0), 0, 25), max = 100 }), true)
	local envelopes = if Json.isArray(answer.envelopes) then answer.envelopes else {}
	local cards = if Json.isObject(answer.cards) then answer.cards else {}
	local agents = if Json.isObject(answer.agents) then answer.agents else {}
	local connected = self:_connectedNets(answer)
	local inbox: Inbox = { messages = {}, rejected = 0, duplicates = 0 }
	local toAck = self.pendingAcks
	self.pendingAcks = {}
	for index, value in envelopes do
		if index > 100 then
			break
		end
		local ok, envelope = pcall(Proto.envelopeFromValue, value)
		if not ok then
			inbox.rejected += 1
			continue
		end
		local key = envelope.from .. " " .. Enc.b64(envelope.id)
		local known = false
		for _, pair in toAck do
			known = known or (pair[1] .. " " .. pair[2] == key)
		end
		if not known then
			table.insert(toAck, { envelope.from, Enc.b64(envelope.id) })
		end
		if self.seen[key] then
			inbox.duplicates += 1
			continue
		end
		local message = self:_open(value, cards, agents, connected)
		if message == nil then
			inbox.rejected += 1
			continue
		end
		self.seen[key] = envelope.iat + envelope.ttl * 1000
		table.insert(self.seenOrder, key)
		while #self.seenOrder > SEEN_MEMORY do
			self.seen[table.remove(self.seenOrder, 1) :: string] = nil
		end
		table.insert(inbox.messages, message)
	end
	if #toAck > 0 then
		local ok, problem = pcall(self.ack, self, toAck)
		if not ok then
			self.pendingAcks = toAck
			inbox.warning = "acknowledging failed, will retry: " .. tostring(problem)
		end
	end
	return inbox
end

--- Acknowledges {sender, envelope id (Base64url)} pairs - the node deletes them.
function Client:ack(list: { { string } }): number
	local removed = 0
	for start = 1, #list, 100 do
		local acks = Json.array()
		for i = start, math.min(#list, start + 99) do
			table.insert(acks, Json.object({ from = list[i][1], id = list[i][2] }))
		end
		local request = Proto.signRequest(self.identity, self:_nodeId(), "ack", Json.object({ acks = acks }), now())
		local answer = self:_post("/v4/ack", Json.canonical(request.raw), true)
		removed += if type(answer.removed) == "number" then answer.removed else 0
	end
	return removed
end

return Client
