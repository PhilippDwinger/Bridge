-- The shared test vectors (sdk/vectors/vectors.json, made by the Rust core) - docs/10 §2.2. lune run tests/vectors.luau
local fs = require("@lune/fs")
local process = require("@lune/process")
local Crypto = require("../src/Crypto")
local Enc = require("../src/Enc")
local Json = require("../src/Json")
local Proto = require("../src/Proto")
local Random = require("../src/Random")

Random.setEntropySource(function()
	return process.spawn("head", { "-c", "64", "/dev/urandom" }).stdout
end)

local V = Json.parse(fs.readFile("../vectors/vectors.json"), 4194304)
local passed, failed = 0, 0

local function test(name: string, fn: () -> ())
	local ok, problem = pcall(fn)
	if ok then
		passed += 1
	else
		failed += 1
		print("FAIL " .. name .. ": " .. tostring(problem))
	end
end

local function equal(actual: any, expected: any, what: string)
	if actual ~= expected then
		error(what .. ": expected " .. tostring(expected) .. " got " .. tostring(actual), 0)
	end
end

local function fails(fn: () -> any, what: string)
	if pcall(fn) then
		error(what .. ": should have failed", 0)
	end
end

local function identity(seed: number)
	return Proto.identity(string.rep(string.char(seed), 32), string.rep(string.char((seed + 100) % 256), 32))
end

local function nullable(value: any): any
	return if value == Json.null then nil else value
end

test("json", function()
	for _, c in V.json.canonical do
		equal(Json.canonical(Json.parse(c["in"], 1048576)), c.out, c["in"])
	end
	for _, text in V.json.invalid do
		fails(function()
			return Json.parse(text, 1048576)
		end, text)
	end
	for _, hex in V.json.invalid_bytes_hex do
		fails(function()
			return Json.parse(Enc.fromHex(hex), 1048576)
		end, hex)
	end
end)

test("encoding", function()
	for _, c in V.encoding.base32 do
		equal(Enc.base32(Enc.fromHex(c.hex)), c.b32, "base32")
	end
	for _, c in V.encoding.b64 do
		equal(Enc.b64(Enc.fromHex(c.hex)), c.b64, "b64")
		equal(Enc.hex(Enc.b64Var(c.b64, "x", 100)), c.hex, "b64 decode")
	end
	for _, text in V.encoding.b64_invalid do
		fails(function()
			return Enc.b64Var(text, "x", 100)
		end, text)
	end
end)

test("identities", function()
	for _, c in V.identities.valid do
		local id = Proto.identity(Enc.b64Var(c.sign_secret, "s", 32), Enc.b64Var(c.box_secret, "b", 32))
		equal(Enc.b64(id.signPublic), c.sign_public, "sign public")
		equal(Enc.b64(id.boxPublic), c.box_public, "box public")
		equal(id.id, c.id, "id")
		local tls = if c.tls then Enc.b64Var(c.tls, "tls", 32) else nil
		local card = id:keyCard(c.role, nullable(c.name), c.iat, c.urls, tls)
		equal(Proto.cardText(card), c.card, "card")
		equal(Proto.parseCard(c.card).id, c.id, "parse")
	end
	for _, c in V.identities.invalid do
		fails(function()
			return Proto.parseCard(c.card)
		end, c.why)
	end
	local five = identity(5)
	equal(Proto.identityFromKeyFile(five:toKeyFile()).id, five.id, "key file")
end)

test("weak keys and malleability", function()
	local w = V.signatures.weak_signature
	for _, key in V.signatures.weak_keys do
		equal(Crypto.verify(Enc.b64Var(key, "k", 32), w.domain, w.message, Enc.b64Var(w.sig, "s", 64)), false, "weak key")
	end
	local m = V.signatures.malleable
	fails(function()
		return Proto.verifyStatement(Proto.parseStatement(m.statement), { Proto.parseCard(m.signer_card) }, 1)
	end, "S+L")
end)

test("statements", function()
	for _, c in V.statements.valid do
		local signers = {}
		for _, seed in c.signers do
			table.insert(signers, identity(seed))
		end
		local body = Json.parse(c.body, 65536)
		local made = if #signers == 1
			then Proto.signStatement(c.kind, c.net, c.iat, c.exp, body, signers[1])
			else Proto.signStatementMulti(c.kind, c.net, c.iat, c.exp, body, signers)
		equal(Json.canonical(made.raw), c.statement, "statement")
		equal(Proto.statementHash(made), c.hash, "hash")
		local cards = {}
		for _, signer in signers do
			table.insert(cards, signer:keyCard("admin", nil, 0))
		end
		equal(#Proto.verifyStatement(Proto.parseStatement(c.statement), cards, #cards), #cards, "verify")
	end
	for _, c in V.statements.invalid do
		fails(function()
			return Proto.parseStatement(c.statement)
		end, c.why)
	end
end)

test("request", function()
	local c = V.request
	local signer = identity(c.signer)
	local made = Proto.signRequest(signer, c.aud, c.op, Json.parse(c.body, 1000), c.iat, Enc.b64Var(c.nonce, "n", 16))
	equal(Json.canonical(made.raw), c.request, "request")
	local card = signer:keyCard("client", nil, 0)
	Proto.verifyRequest(Proto.requestFromValue(Json.parse(c.request, 65536)), card, c.aud, c.iat + 1000)
	fails(function()
		return Proto.verifyRequest(Proto.requestFromValue(Json.parse(c.request, 65536)), card, c.aud, c.iat + 6 * 60 * 1000)
	end, "expired")
	fails(function()
		return Proto.verifyRequest(Proto.requestFromValue(Json.parse(c.tampered, 65536)), card, c.aud, c.iat + 1000)
	end, "tampered")
end)

test("content", function()
	for _, c in V.content.valid do
		equal(Proto.contentBytes(Proto.parseContent(c.content)), c.content, c.label)
	end
	for _, text in V.content.invalid do
		fails(function()
			return Proto.parseContent(text)
		end, text)
	end
end)

test("envelopes", function()
	local c = V.envelope
	local sender, recipient = identity(c.sender), identity(c.recipient)
	local card = sender:keyCard("client", nil, 0)
	for _, pair in { { c.plain, nil }, { c.to_net.envelope, c.to_net.dnet } } do
		local envelope = Proto.parseEnvelope(pair[1])
		Proto.checkEnvelopeTime(envelope, c.now)
		equal(envelope.dnet, pair[2], "dnet")
		equal(Proto.open(envelope, recipient, card), c.plaintext, "plaintext")
		fails(function()
			return Proto.open(envelope, sender, card)
		end, "not the recipient")
	end
	for _, bad in c.invalid do
		fails(function()
			return Proto.open(Proto.parseEnvelope(bad.envelope), recipient, card)
		end, bad.why)
	end
	local alice, bob = identity(1), identity(2)
	local a = Proto.seal(alice, identity(9).id, bob:keyCard("client", nil, 0), "hallo", 1000, 60)
	local b = Proto.seal(alice, identity(9).id, bob:keyCard("client", nil, 0), "hallo", 1000, 60)
	if Json.canonical(a.raw) == Json.canonical(b.raw) then
		error("N1", 0)
	end
	equal(Proto.open(Proto.parseEnvelope(Json.canonical(a.raw)), bob, alice:keyCard("client", nil, 0)), "hallo", "own")
end)

test("pow", function()
	local c = V.pow
	equal(Enc.b64(Proto.solvePuzzle(Json.parse(c.puzzle, 2000), Proto.parseCard(c.node_card), 16777216)), c.solution, "solution")
end)

test("links", function()
	for _, c in V.links.valid do
		local link = Proto.parseLink(c.link)
		equal(link.net, c.net, "net")
		equal(link.gateway, c.gateway, "gw")
		equal(link.code, nullable(c.code), "code")
		equal(link.node, nullable(c.node), "node")
		equal(if link.tls then Enc.b64(link.tls) else nil, nullable(c.tls), "tls")
	end
	for _, text in V.links.invalid do
		fails(function()
			return Proto.parseLink(text)
		end, text)
	end
end)

test("agents", function()
	local c = V.agents
	local valid = c.valid
	local statement = Proto.parseStatement(valid.statement)
	local agent = Proto.checkAgent(statement, c.net, c.now)
	equal(agent.agent, valid.agent, "agent")
	equal(agent.owner.id, valid.owner, "owner")
	equal(agent.note, valid.note, "note")
	equal(agent.rate, valid.rate, "rate")
	equal(table.concat(agent.scopes, ","), table.concat(valid.scopes, ","), "scopes")
	equal(table.concat(agent.to :: { string }, ","), table.concat(valid.to, ","), "to")
	equal(Json.canonical(Proto.agentBody(agent)), Json.canonical(statement.body), "body")
	for _, bad in c.invalid do
		fails(function()
			return Proto.checkAgent(Proto.parseStatement(bad.statement), bad.net or c.net, bad.now or c.now)
		end, bad.why)
	end
end)

test("federation", function()
	local c = V.federation
	local master = Proto.parseCard(c.master)
	equal(Proto.checkFederation(Json.parse(c.valid.statement, 65536), c.net, master, c.valid.peer, c.now), true, "valid")
	for _, bad in c.invalid do
		equal(Proto.checkFederation(Json.parse(bad.statement, 65536), c.net, master, bad.peer, c.now), false, bad.why)
	end
end)

print(string.format("vectors: %d passed, %d failed", passed, failed))
if failed > 0 then
	process.exit(1)
end
