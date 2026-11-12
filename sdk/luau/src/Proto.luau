--!strict
--[[
	The Bridge 4 formats (docs/04, docs/06 §7, docs/10): key cards, identities, statements, signed requests, content,
	envelopes, proof-of-work puzzles, join links, agent cards, federation proofs, the join check. Same rules as the
	Rust core; every `from*`/`parse` checks fully and raises a BridgeError (see Errors) on anything wrong.
]]

local Crypto = require("./Crypto")
local Enc = require("./Enc")
local Errors = require("./Errors")
local Json = require("./Json")
local Random = require("./Random")

local Proto = {}

local CLOCK_SKEW_MS = 5 * 60 * 1000
local format = Errors.format

local function isInt(value: any): boolean
	return type(value) == "number" and value == math.floor(value) and math.abs(value) <= Json.MAX_SAFE_INTEGER
end

local function object(value: any, what: string): { [string]: any }
	if not Json.isObject(value) then
		format(what .. ": not an object")
	end
	return value
end

local function list(value: any, what: string): { any }
	if type(value) ~= "table" or not (Json.isArray(value) or next(value) == nil) or value == Json.null then
		format(what .. ": not a list")
	end
	return value
end

local function count(t: { [any]: any }): number
	local n = 0
	for _ in t do
		n += 1
	end
	return n
end

local function distinct(items: { any }): boolean
	local seen = {}
	for _, item in items do
		if seen[item] then
			return false
		end
		seen[item] = true
	end
	return true
end

function Proto.checkId(text: any): string
	if type(text) ~= "string" or #text ~= 32 or string.match(text, "^[a-z2-7]+$") == nil then
		format("id: expected 32 characters of base32")
	end
	return text
end

function Proto.idOf(signPublic: string): string
	return Enc.base32(string.sub(Crypto.sha256(signPublic), 1, 20))
end

local function authorityOk(authority: string): boolean
	local port: string? = nil
	if string.sub(authority, 1, 1) == "[" then
		local close = string.find(authority, "]", 1, true)
		if not close then
			return false
		end
		local ip, after = string.sub(authority, 2, close - 1), string.sub(authority, close + 1)
		if ip == "" or not string.find(ip, ":", 1, true) or string.match(ip, "^[0-9a-fA-F:.]+$") == nil then
			return false
		end
		-- at most one "::" and at most 8 groups (a light IPv6 check)
		local _, doubles = string.gsub(ip, "::", "")
		local _, colons = string.gsub(ip, ":", "")
		if doubles > 1 or colons > 7 then
			return false
		end
		if after ~= "" then
			if string.sub(after, 1, 1) ~= ":" then
				return false
			end
			port = string.sub(after, 2)
		end
	else
		local colon = string.find(authority, ":", 1, true)
		local host = if colon then string.sub(authority, 1, colon - 1) else authority
		if colon then
			port = string.sub(authority, colon + 1)
		end
		if host == "" then
			return false
		end
		for label in string.gmatch(host .. ".", "([^.]*)%.") do
			if string.match(label, "^[A-Za-z0-9_%-]+$") == nil then
				return false
			end
		end
	end
	if port ~= nil then
		if string.match(port, "^%d%d?%d?%d?%d?$") == nil then
			return false
		end
		local number = tonumber(port) :: number
		if number < 1 or number > 65535 then
			return false
		end
	end
	return true
end

--- One rule for every address (docs/06 §2): http(s)://host[:port][/path], at most 200 characters.
function Proto.checkUrl(url: any): string
	local ok = type(url) == "string" and #url <= 200
	if ok then
		local rest = if string.sub(url, 1, 8) == "https://" then string.sub(url, 9)
			elseif string.sub(url, 1, 7) == "http://" then string.sub(url, 8)
			else nil
		ok = rest ~= nil
		if rest then
			local slash = string.find(rest, "/", 1, true)
			local authority = if slash then string.sub(rest, 1, slash - 1) else rest
			local path = if slash then string.sub(rest, slash) else ""
			ok = authorityOk(authority)
				and (path == "" or (string.match(path, "^/[A-Za-z0-9/%._~%-]*$") ~= nil and not string.find(path .. "/", "/%.%.?/")))
		end
	end
	if not ok then
		format("url: expected http(s)://host[:port][/path]")
	end
	return url
end

-- ---------------------------------------------------------------------------------------------------------------
-- key cards and identities

export type KeyCard = { raw: { [string]: any }, id: string, sign: string, box: string, role: string, urls: { string } }

local ROLES = { client = true, node = true, net = true, admin = true, app = true }
Proto.MAX_KEY_CARD_BYTES = 2048

function Proto.cardFromValue(value: any): KeyCard
	local card = object(value, "key card")
	if Json.depth(card) > 4 or #Json.canonical(card) > Proto.MAX_KEY_CARD_BYTES then
		Errors.raise("TOO_LARGE", "key card")
	end
	if card.v ~= 4 or card.t ~= "key" then
		format("key card: wrong version or type")
	end
	Proto.checkId(card.id)
	local sign = Enc.b64Fixed(card.sign, "sign", 32)
	local box = Enc.b64Fixed(card.box, "box", 32)
	if not ROLES[card.role] then
		format("role: unknown")
	end
	if card.name ~= nil and (type(card.name) ~= "string" or (utf8.len(card.name) or 999) > 64) then
		format("name: too long or not a string")
	end
	if not isInt(card.iat) or card.iat < 0 then
		format("iat")
	end
	local urls = {}
	if card.urls ~= nil then
		local given = list(card.urls, "urls")
		if #given < 1 or #given > 4 or not distinct(given) then
			format("urls: 1..=4 distinct addresses")
		end
		for _, url in given do
			table.insert(urls, Proto.checkUrl(url))
		end
	end
	if card.tls ~= nil then
		Enc.b64Fixed(card.tls, "tls", 32)
	end
	if (card.urls ~= nil or card.tls ~= nil) and card.role ~= "node" then
		format("urls/tls: only on node cards")
	end
	local signature = Enc.b64Fixed(card.sig, "sig", 64)
	if Proto.idOf(sign) ~= card.id then
		Errors.signature()
	end
	if not Crypto.verify(sign, "key", Json.canonicalWithout(card, { "sig" }), signature) then
		Errors.signature()
	end
	return { raw = Json.copy(card), id = card.id, sign = sign, box = box, role = card.role, urls = urls }
end

function Proto.parseCard(text: string): KeyCard
	return Proto.cardFromValue(Json.parse(text, Proto.MAX_KEY_CARD_BYTES))
end

function Proto.cardText(card: KeyCard): string
	return Json.canonical(card.raw)
end

export type Identity = {
	id: string,
	signPublic: string,
	boxPublic: string,
	sign: (self: Identity, domain: string, data: string) -> string,
	agree: (self: Identity, peer: string) -> string?,
	keyCard: (self: Identity, role: string?, name: string?, iat: number?, urls: { string }?, tls: string?) -> KeyCard,
	toKeyFile: (self: Identity) -> string,
}

--- An identity from its secrets (32 bytes each). Keep the secrets on the server (ServerStorage), never on clients.
function Proto.identity(signSecret: string, boxSecret: string): Identity
	if #signSecret ~= 32 or #boxSecret ~= 32 then
		format("secrets are 32 bytes")
	end
	local signPublic = Crypto.ed25519Public(signSecret)
	local self = {
		signPublic = signPublic,
		boxPublic = Crypto.x25519Public(boxSecret),
		id = Proto.idOf(signPublic),
	}
	function self.sign(_: any, domain: string, data: string): string
		return Crypto.sign(signSecret, domain, data)
	end
	function self.agree(_: any, peer: string): string?
		return Crypto.x25519(boxSecret, peer)
	end
	function self.toKeyFile(_: any): string
		return Json.canonical(Json.object({ v = 4, t = "secret", sign = Enc.b64(signSecret), box = Enc.b64(boxSecret) }))
	end
	function self.keyCard(me: any, role: string?, name: string?, iat: number?, urls: { string }?, tls: string?): KeyCard
		local card = Json.object({
			v = 4,
			t = "key",
			id = me.id,
			sign = Enc.b64(me.signPublic),
			box = Enc.b64(me.boxPublic),
			role = role or "client",
			iat = iat or 0,
		})
		if name ~= nil then
			card.name = name
		end
		if urls and #urls > 0 then
			card.urls = Json.array(table.clone(urls))
		end
		if tls then
			card.tls = Enc.b64(tls)
		end
		card.sig = Enc.b64(Crypto.sign(signSecret, "key", Json.canonical(card)))
		return Proto.cardFromValue(card)
	end
	return self :: any
end

--- A new identity (needs an entropy source, see Random).
function Proto.generateIdentity(): Identity
	return Proto.identity(Random.bytes(32), Random.bytes(32))
end

--- From the text of a key file {"v":4,"t":"secret","sign","box"} (the node's format).
function Proto.identityFromKeyFile(text: string): Identity
	local value = object(Json.parse(text, 1024), "key file")
	if value.v ~= 4 or value.t ~= "secret" then
		format("key file: wrong form")
	end
	return Proto.identity(Enc.b64Fixed(value.sign, "sign", 32), Enc.b64Fixed(value.box, "box", 32))
end

-- ---------------------------------------------------------------------------------------------------------------
-- statements

export type Statement = {
	raw: { [string]: any },
	kind: string,
	net: string,
	iat: number,
	exp: number,
	body: { [string]: any },
	signers: { { any } },
}

local RESERVED = { env = true, key = true, rq = true, pow = true, part = true }
Proto.MAX_STATEMENT_BYTES = 64 * 1024

function Proto.statementFromValue(value: any): Statement
	local raw = object(value, "statement")
	if #Json.canonical(raw) > Proto.MAX_STATEMENT_BYTES then
		Errors.raise("TOO_LARGE", "statement")
	end
	if raw.v ~= 4 then
		format("statement: wrong version")
	end
	if type(raw.t) ~= "string" or string.match(raw.t, "^[a-z]+$") == nil or #raw.t > 16 or RESERVED[raw.t] then
		format("statement: bad kind")
	end
	Proto.checkId(raw.net)
	if not isInt(raw.iat) or not isInt(raw.exp) or raw.iat < 0 or raw.exp <= raw.iat or raw.exp - raw.iat > 2 * 366 * 24 * 3600 * 1000 then
		format("statement: bad iat/exp")
	end
	object(raw.body, "statement body")
	local signers = {}
	if raw.sig ~= nil and raw.sigs == nil then
		table.insert(signers, { Proto.checkId(raw.iss), Enc.b64Fixed(raw.sig, "sig", 64) })
	elseif raw.sigs ~= nil and raw.sig == nil and Json.isArray(raw.sigs) and #raw.sigs >= 1 and #raw.sigs <= 16 then
		if raw.iss ~= nil then
			format("statement: iss together with sigs")
		end
		for _, entry in raw.sigs do
			if not Json.isObject(entry) or count(entry) ~= 2 or entry.iss == nil or entry.sig == nil then
				format("sigs: entries are exactly {iss, sig}")
			end
			local issuer = Proto.checkId(entry.iss)
			if #signers > 0 and signers[#signers][1] >= issuer then
				format("sigs: signers must be strictly ascending by iss")
			end
			table.insert(signers, { issuer, Enc.b64Fixed(entry.sig, "sig", 64) })
		end
	else
		format("statement: needs either sig or sigs (1..=16)")
	end
	return { raw = Json.copy(raw), kind = raw.t, net = raw.net, iat = raw.iat, exp = raw.exp, body = raw.body, signers = signers }
end

function Proto.parseStatement(text: string): Statement
	return Proto.statementFromValue(Json.parse(text, Proto.MAX_STATEMENT_BYTES))
end

function Proto.signStatement(kind: string, net: string, iat: number, exp: number, body: { [string]: any }, signer: Identity): Statement
	local raw = Json.object({ v = 4, t = kind, net = net, iat = iat, exp = exp, body = body, iss = signer.id })
	raw.sig = Enc.b64(signer:sign(kind, Json.canonical(raw)))
	return Proto.statementFromValue(raw)
end

function Proto.signStatementMulti(kind: string, net: string, iat: number, exp: number, body: { [string]: any }, signers: { Identity }): Statement
	local raw = Json.object({ v = 4, t = kind, net = net, iat = iat, exp = exp, body = body })
	local data = Json.canonical(raw)
	local ordered = table.clone(signers)
	table.sort(ordered, function(a, b)
		return a.id < b.id
	end)
	local sigs = Json.array()
	for _, signer in ordered do
		table.insert(sigs, Json.object({ iss = signer.id, sig = Enc.b64(signer:sign(kind, data)) }))
	end
	raw.sigs = sigs
	return Proto.statementFromValue(raw)
end

function Proto.claimedSigners(statement: Statement): { string }
	local out = {}
	for _, signer in statement.signers do
		table.insert(out, signer[1])
	end
	return out
end

--- Verifies every listed signature with `cards`; raises below `threshold`. Returns the signers.
function Proto.verifyStatement(statement: Statement, cards: { KeyCard }, threshold: number): { string }
	local data = Json.canonicalWithout(statement.raw, { if statement.raw.sigs ~= nil then "sigs" else "sig" })
	local valid = {}
	for _, signer in statement.signers do
		local card: KeyCard? = nil
		for _, candidate in cards do
			if candidate.id == signer[1] then
				card = candidate
			end
		end
		if card == nil or not Crypto.verify((card :: KeyCard).sign, statement.kind, data, signer[2]) then
			Errors.signature()
		end
		table.insert(valid, signer[1])
	end
	if threshold == 0 or #valid < threshold then
		Errors.signature()
	end
	return valid
end

function Proto.checkTime(statement: Statement, nowMs: number)
	if statement.iat > nowMs + CLOCK_SKEW_MS then
		Errors.raise("NOT_YET_VALID")
	end
	if nowMs >= statement.exp then
		Errors.raise("EXPIRED")
	end
end

function Proto.statementHash(statement: Statement): string
	return Enc.b64(Crypto.sha256(Json.canonicalWithout(statement.raw, { "sig", "sigs" })))
end

-- ---------------------------------------------------------------------------------------------------------------
-- signed requests

export type Request = { raw: { [string]: any }, aud: string, iss: string, iat: number, op: string, body: { [string]: any } }

function Proto.requestFromValue(value: any): Request
	local raw = object(value, "request")
	if raw.v ~= 4 or raw.t ~= "rq" then
		format("request: wrong version or type")
	end
	if type(raw.op) ~= "string" or #raw.op > 24 or string.match(raw.op, "^[a-z%-]+$") == nil then
		format("op: bad name")
	end
	object(raw.body, "request body")
	if not isInt(raw.iat) or raw.iat < 0 then
		format("iat")
	end
	Proto.checkId(raw.aud)
	Proto.checkId(raw.iss)
	Enc.b64Fixed(raw.n, "n", 16)
	Enc.b64Fixed(raw.sig, "sig", 64)
	return { raw = Json.copy(raw), aud = raw.aud, iss = raw.iss, iat = raw.iat, op = raw.op, body = raw.body }
end

--- Signs `op` with `body` for node `aud` (`nonce` random unless given - tests only).
function Proto.signRequest(signer: Identity, aud: string, op: string, body: { [string]: any }, iat: number, nonce: string?): Request
	local raw = Json.object({ v = 4, t = "rq", aud = aud, iss = signer.id, iat = iat, n = Enc.b64(nonce or Random.bytes(16)), op = op, body = body })
	raw.sig = Enc.b64(signer:sign("rq", Json.canonical(raw)))
	if #Json.canonical(raw) > 64 * 1024 then
		Errors.raise("TOO_LARGE", "request")
	end
	return Proto.requestFromValue(raw)
end

function Proto.verifyRequest(request: Request, card: KeyCard, node: string, nowMs: number)
	if request.aud ~= node or card.id ~= request.iss then
		Errors.signature()
	end
	if request.iat > nowMs + CLOCK_SKEW_MS then
		Errors.raise("NOT_YET_VALID")
	end
	if nowMs - request.iat > CLOCK_SKEW_MS then
		Errors.raise("EXPIRED")
	end
	if not Crypto.verify(card.sign, "rq", Json.canonicalWithout(request.raw, { "sig" }), Enc.b64Fixed(request.raw.sig, "sig", 64)) then
		Errors.signature()
	end
end

-- ---------------------------------------------------------------------------------------------------------------
-- content

export type Content = { kind: string, ctype: string, text: string?, data: string?, reply: string?, card: KeyCard? }

local TYPES = { direct = true, task = true, response = true, progress = true, event = true, instruction = true, stream = true }
Proto.MAX_PLAINTEXT_BYTES = 180 * 1024

local function ctypeOk(ctype: any): boolean
	return type(ctype) == "string" and #ctype >= 1 and #ctype <= 64 and string.match(ctype, "^[A-Za-z0-9/%.%+%-;=_]+$") ~= nil
end

function Proto.contentBytes(content: Content): string
	if not TYPES[content.kind] or content.kind == "stream" then
		format("type: unknown (no streams here)")
	end
	if not ctypeOk(content.ctype) then
		format("ctype: bad")
	end
	if (content.text == nil) == (content.data == nil) then
		format("content: exactly one of text, data")
	end
	local out = Json.object({ v = 4, type = content.kind, ctype = content.ctype })
	if content.text ~= nil then
		out.body = content.text
	else
		out.data = Enc.b64(content.data :: string)
	end
	if content.reply then
		out.reply = Enc.b64(content.reply)
	end
	if content.card then
		out.card = content.card.raw
	end
	local bytes = Json.canonical(out)
	if #bytes > Proto.MAX_PLAINTEXT_BYTES then
		Errors.raise("TOO_LARGE", "content")
	end
	return bytes
end

function Proto.parseContent(bytes: string): Content
	local value = object(Json.parse(bytes, Proto.MAX_PLAINTEXT_BYTES), "content")
	if value.v ~= 4 then
		format("content: wrong version")
	end
	if not TYPES[value.type] then
		format("type: unknown")
	end
	if not ctypeOk(value.ctype) then
		format("ctype: bad")
	end
	local content: Content = { kind = value.type, ctype = value.ctype }
	local has = (if value.body ~= nil then "b" else "-") .. (if value.data ~= nil then "d" else "-") .. (if value.stream ~= nil then "s" else "-")
	if has == "b--" and value.type ~= "stream" then
		if type(value.body) ~= "string" then
			format("body: not a string")
		end
		content.text = value.body
	elseif has == "-d-" and value.type ~= "stream" then
		content.data = Enc.b64Var(value.data, "data", Proto.MAX_PLAINTEXT_BYTES)
	elseif has == "--s" and value.type == "stream" then
		content.data = nil -- stream heads are read but not followed by this SDK
	else
		format("content: exactly one of body, data, stream (stream only for streams)")
	end
	if value.reply ~= nil then
		content.reply = Enc.b64Fixed(value.reply, "reply", 16)
	end
	if value.card ~= nil then
		content.card = Proto.cardFromValue(value.card)
	end
	return content
end

-- ---------------------------------------------------------------------------------------------------------------
-- envelopes (N1: one-time key and nonce only made here)

export type Envelope = {
	raw: { [string]: any },
	id: string,
	net: string,
	dnet: string?,
	from: string,
	to: string,
	iat: number,
	ttl: number,
}

local KINDS = { msg = true, req = true, res = true, evt = true, ack = true }
Proto.MAX_ENVELOPE_BYTES = 256 * 1024

local function envelopeKey(shared: string, epk: string, recipientBox: string, id: string): string
	return Crypto.hkdf32(shared, epk .. recipientBox, "bridge4/env/v1" .. id)
end

function Proto.envelopeFromValue(value: any): Envelope
	local raw = object(value, "envelope")
	if Json.depth(raw) > 8 then
		format("envelope: nested too deep")
	end
	if raw.v ~= 4 or raw.t ~= "env" then
		format("envelope: wrong version or type")
	end
	if not isInt(raw.iat) or not isInt(raw.ttl) or raw.iat < 0 or raw.ttl <= 0 or raw.ttl > 7 * 24 * 3600 then
		format("iat/ttl out of range")
	end
	if #Enc.b64Var(raw.ct, "ct", Proto.MAX_PLAINTEXT_BYTES + 16) < 16 then
		format("ct: too short")
	end
	local net = Proto.checkId(raw.net)
	if raw.dnet ~= nil and Proto.checkId(raw.dnet) == net then
		format("dnet: must be another network than net")
	end
	Proto.checkId(raw.from)
	Proto.checkId(raw.to)
	if not KINDS[raw.kind] then
		format("kind: unknown")
	end
	local id = Enc.b64Fixed(raw.id, "id", 16)
	Enc.b64Fixed(raw.epk, "epk", 32)
	Enc.b64Fixed(raw.n, "n", 12)
	Enc.b64Fixed(raw.sig, "sig", 64)
	return { raw = Json.copy(raw), id = id, net = net, dnet = raw.dnet, from = raw.from, to = raw.to, iat = raw.iat, ttl = raw.ttl }
end

function Proto.parseEnvelope(text: string): Envelope
	return Proto.envelopeFromValue(Json.parse(text, Proto.MAX_ENVELOPE_BYTES))
end

function Proto.seal(sender: Identity, net: string, to: KeyCard, plaintext: string, iat: number, ttl: number, dnet: string?): Envelope
	if #plaintext > Proto.MAX_PLAINTEXT_BYTES then
		Errors.raise("TOO_LARGE", "plaintext")
	end
	if dnet ~= nil and Proto.checkId(dnet) == net then
		format("dnet: must be another network than net")
	end
	local id, nonce, oneTime = Random.bytes(16), Random.bytes(12), Random.bytes(32)
	local epk = Crypto.x25519Public(oneTime)
	local shared = Crypto.x25519(oneTime, to.box)
	if shared == nil then
		Errors.raise("CANNOT_OPEN")
	end
	local key = envelopeKey(shared :: string, epk, to.box, id)
	local raw = Json.object({
		v = 4,
		t = "env",
		id = Enc.b64(id),
		net = net,
		from = sender.id,
		to = to.id,
		iat = iat,
		ttl = ttl,
		kind = "msg",
		epk = Enc.b64(epk),
		n = Enc.b64(nonce),
	})
	if dnet ~= nil then
		raw.dnet = dnet
	end
	raw.ct = Enc.b64(Crypto.aeadSeal(key, nonce, plaintext, Json.canonical(raw)))
	raw.sig = Enc.b64(sender:sign("env", Json.canonical(raw)))
	return Proto.envelopeFromValue(raw)
end

function Proto.verifyEnvelope(envelope: Envelope, sender: KeyCard)
	if sender.id ~= envelope.from then
		Errors.signature()
	end
	if not Crypto.verify(sender.sign, "env", Json.canonicalWithout(envelope.raw, { "sig" }), Enc.b64Fixed(envelope.raw.sig, "sig", 64)) then
		Errors.signature()
	end
end

function Proto.checkEnvelopeTime(envelope: Envelope, nowMs: number)
	if envelope.iat > nowMs + CLOCK_SKEW_MS then
		Errors.raise("NOT_YET_VALID")
	end
	if nowMs >= envelope.iat + envelope.ttl * 1000 then
		Errors.raise("EXPIRED")
	end
end

--- Verifies the sender's signature and decrypts (only the recipient can).
function Proto.open(envelope: Envelope, recipient: Identity, sender: KeyCard): string
	Proto.verifyEnvelope(envelope, sender)
	if recipient.id ~= envelope.to then
		Errors.raise("CANNOT_OPEN")
	end
	local epk = Enc.b64Fixed(envelope.raw.epk, "epk", 32)
	local shared = recipient:agree(epk)
	if shared == nil then
		Errors.raise("CANNOT_OPEN")
	end
	local key = envelopeKey(shared :: string, epk, recipient.boxPublic, envelope.id)
	local plaintext = Crypto.aeadOpen(key, Enc.b64Fixed(envelope.raw.n, "n", 12), Enc.b64Var(envelope.raw.ct, "ct", Proto.MAX_PLAINTEXT_BYTES + 16),
		Json.canonicalWithout(envelope.raw, { "ct", "sig" }))
	if plaintext == nil then
		Errors.raise("CANNOT_OPEN")
	end
	return plaintext :: string
end

-- ---------------------------------------------------------------------------------------------------------------
-- proof of work

function Proto.solvePuzzle(value: any, node: KeyCard, maxTries: number): string
	local raw = object(value, "puzzle")
	if raw.v ~= 4 or raw.t ~= "pow" or not isInt(raw.bits) or raw.bits < 0 or raw.bits > 28 or not isInt(raw.exp) then
		format("puzzle: bad form")
	end
	Enc.b64Fixed(raw.nonce, "nonce", 16)
	if raw.node ~= node.id then
		Errors.signature()
	end
	if not Crypto.verify(node.sign, "pow", Json.canonicalWithout(raw, { "sig" }), Enc.b64Fixed(raw.sig, "sig", 64)) then
		Errors.signature()
	end
	local prefix = Json.canonical(raw)
	local bits = raw.bits
	for counter = 0, maxTries - 1 do
		local candidate = string.pack(">I4I4", math.floor(counter / 4294967296), counter % 4294967296)
		local digest = Crypto.sha256(prefix .. candidate)
		local zeros = 0
		for i = 1, 32 do
			local byte = string.byte(digest, i)
			if byte == 0 then
				zeros += 8
			else
				while byte < 128 do
					zeros += 1
					byte *= 2
				end
				break
			end
		end
		if zeros >= bits then
			return candidate
		end
	end
	return Errors.untrusted("proof of work too hard")
end

-- ---------------------------------------------------------------------------------------------------------------
-- join links

export type JoinLink = { net: string, gateway: string, code: string?, node: string?, tls: string? }

local function decodePercent(text: string): string
	local out = {}
	local i = 1
	while i <= #text do
		local c = string.sub(text, i, i)
		if c == "%" then
			local hex = string.sub(text, i + 1, i + 2)
			if string.match(hex, "^%x%x$") == nil then
				format("join link: bad % escape")
			end
			table.insert(out, string.char(tonumber(hex, 16) :: number))
			i += 3
		else
			table.insert(out, c)
			i += 1
		end
	end
	local decoded = table.concat(out)
	if string.match(decoded, "^[\33-\126]*$") == nil then
		format("join link: only printable ASCII")
	end
	return decoded
end

function Proto.parseLink(text: string): JoinLink
	if #text > 1024 then
		Errors.raise("TOO_LARGE", "join link")
	end
	text = string.match(text, "^%s*(.-)%s*$") :: string
	local prefix = "bridge4://join?"
	if string.sub(text, 1, #prefix) ~= prefix then
		format("join link: must start with " .. prefix)
	end
	local found: { [string]: string } = {}
	local pairs_ = string.split(string.sub(text, #prefix + 1), "&")
	for index, pair in pairs_ do
		if index > 8 then
			format("join link: too many parameters")
		end
		local equals = string.find(pair, "=", 1, true)
		if not equals then
			format("join link: key=value")
		end
		local key = string.sub(pair, 1, (equals :: number) - 1)
		if key == "net" or key == "gw" or key == "code" or key == "node" or key == "tls" then
			if found[key] ~= nil then
				format("join link: " .. key .. " twice")
			end
			found[key] = decodePercent(string.sub(pair, (equals :: number) + 1))
		end
	end
	if found.net == nil or found.gw == nil then
		format("join link: net and gw needed")
	end
	local link: JoinLink = { net = Proto.checkId(found.net), gateway = Proto.checkUrl(found.gw) }
	if found.code ~= nil then
		if #found.code < 4 or #found.code > 64 or string.match(found.code, "^[A-Za-z0-9%-]+$") == nil then
			format("code: 4-64 of A-Z a-z 0-9 -")
		end
		link.code = found.code
	end
	if found.node ~= nil then
		link.node = Proto.checkId(found.node)
		if link.node == link.net then
			format("join link: node is the network key")
		end
	end
	if found.tls ~= nil then
		link.tls = Enc.b64Fixed(found.tls, "join link: tls", 32)
		if link.node == nil then
			format("join link: tls needs node")
		end
	end
	return link
end

-- ---------------------------------------------------------------------------------------------------------------
-- agents (docs/10 §3)

export type Agent = {
	agent: string,
	card: KeyCard,
	owner: KeyCard,
	node: string,
	scopes: { string },
	to: { string }?,
	rate: number,
	note: string?,
}

local AGENT_FIELDS = { agent = true, card = true, owner = true, node = true, scopes = true, to = true, rate = true, note = true }

function Proto.agentFromBody(body: any): Agent
	local value = object(body, "agent")
	for key in value do
		if not AGENT_FIELDS[key] then
			format("agent: unknown field " .. tostring(key))
		end
	end
	local agent = Proto.checkId(value.agent)
	local card = Proto.cardFromValue(value.card)
	local owner = Proto.cardFromValue(value.owner)
	if card.id ~= agent or card.role ~= "client" then
		format("agent: card must be the agent's client card")
	end
	if (owner.role ~= "client" and owner.role ~= "admin") or owner.id == agent then
		format("agent: bad owner card")
	end
	local node = Proto.checkId(value.node)
	local scopes = list(value.scopes, "agent scopes")
	if #scopes < 1 or #scopes > 2 or not distinct(scopes) then
		format("agent scopes")
	end
	for _, scope in scopes do
		if scope ~= "send" and scope ~= "receive" then
			format("agent scopes: only send and receive")
		end
	end
	local to: { string }? = nil
	if value.to ~= nil then
		local given = list(value.to, "agent to")
		if #given < 1 or #given > 32 or not distinct(given) then
			format("agent to: 1..=32 distinct ids")
		end
		local ids = {}
		for _, id in given do
			table.insert(ids, Proto.checkId(id))
		end
		to = ids
	end
	local rate = 60
	if value.rate ~= nil then
		if not isInt(value.rate) or value.rate < 1 or value.rate > 3600 then
			format("agent rate")
		end
		rate = value.rate
	end
	local note: string? = nil
	if value.note ~= nil then
		local length = if type(value.note) == "string" then utf8.len(value.note) else nil
		if length == nil or length < 1 or length > 64 then
			format("agent note: 1..=64 characters")
		end
		for _, code in utf8.codes(value.note) do
			if code < 0x20 or (code >= 0x7f and code <= 0x9f) then
				format("agent note: no control characters")
			end
		end
		note = value.note
	end
	local sorted = table.clone(scopes)
	table.sort(sorted)
	return { agent = agent, card = card, owner = owner, node = node, scopes = sorted, to = to, rate = rate, note = note }
end

function Proto.agentBody(agent: Agent): { [string]: any }
	local body = Json.object({
		agent = agent.agent,
		card = agent.card.raw,
		owner = agent.owner.raw,
		node = agent.node,
		scopes = Json.array(table.clone(agent.scopes)),
	})
	if agent.to then
		body.to = Json.array(table.clone(agent.to))
	end
	if agent.rate ~= 60 then
		body.rate = agent.rate
	end
	if agent.note ~= nil then
		body.note = agent.note
	end
	Proto.agentFromBody(body)
	return body
end

--- Checks an agent statement fully: kind, network, the owner alone signed it, at most 30 days, time, signature.
function Proto.checkAgent(statement: Statement, net: string, nowMs: number): Agent
	if statement.kind ~= "agent" then
		format("expected an agent statement")
	end
	local agent = Proto.agentFromBody(statement.body)
	if statement.net ~= net then
		format("agent: other network")
	end
	local signers = Proto.claimedSigners(statement)
	if #signers ~= 1 or signers[1] ~= agent.owner.id then
		Errors.signature()
	end
	if statement.exp - statement.iat > 30 * 24 * 3600 * 1000 then
		format("agent: lifetime over 30 days")
	end
	Proto.checkTime(statement, nowMs)
	Proto.verifyStatement(statement, { agent.owner }, 1)
	return agent
end

-- ---------------------------------------------------------------------------------------------------------------
-- federation proofs and the join check

--- Whether `value` is a federation statement of `net` with `peer`, by the net key alone, in effect (docs/10 §6.3).
function Proto.checkFederation(value: any, net: string, master: KeyCard, peer: string, nowMs: number): boolean
	local ok = pcall(function()
		local statement = Proto.statementFromValue(value)
		local signers = Proto.claimedSigners(statement)
		local scope = statement.body.scope
		if statement.kind ~= "federation" or statement.net ~= net or #signers ~= 1 or signers[1] ~= net
			or statement.body.peer ~= peer or not Json.isArray(scope) or #scope ~= 1 or scope[1] ~= "messages"
			or master.id ~= net or master.role ~= "net" then
			format("not a federation proof")
		end
		Proto.checkTime(statement, nowMs)
		Proto.verifyStatement(statement, { master }, 1)
	end)
	return ok
end

--- What a client checks before joining at gateway `node` (docs/06 §7).
function Proto.gatewayInLog(net: string, node: string, entries: { Statement })
	if #entries == 0 then
		Errors.untrusted("network log: empty")
	end
	local genesis = entries[1]
	local master = Proto.cardFromValue(genesis.body.card)
	local signers = Proto.claimedSigners(genesis)
	if genesis.kind ~= "manifest" or genesis.net ~= net or master.id ~= net or master.role ~= "net" or genesis.body.version ~= 1
		or #signers ~= 1 or signers[1] ~= net then
		Errors.untrusted("network log: entry 0 is not the genesis manifest of this network")
	end
	Proto.verifyStatement(genesis, { master }, 1)
	if Json.isArray(genesis.body.gateways) then
		for _, entry in genesis.body.gateways do
			if Json.isObject(entry) and entry.id == node then
				return
			end
		end
	end
	local cards = { master }
	for _, statement in entries do
		local by = Proto.claimedSigners(statement)
		local rights = statement.body.rights
		if statement.kind == "delegation" and statement.net == net and #by == 1 and by[1] == net and Json.isArray(rights)
			and table.find(rights, "seals") then
			pcall(function()
				Proto.verifyStatement(statement, { master }, 1)
				local card = Proto.cardFromValue(statement.body.card)
				if card.role == "admin" and statement.body.admin == card.id and #cards < 10000 then
					table.insert(cards, card)
				end
			end)
		end
	end
	for _, seal in entries do
		local body = seal.body
		if seal.kind == "seal" and seal.net == net and body.subject == node and isInt(body.level) and body.level >= 2
			and Json.isArray(body.services) and table.find(body.services, "gateway") then
			if pcall(Proto.verifyStatement, seal, cards, #seal.signers) then
				return
			end
		end
	end
	Errors.untrusted("network log: the gateway is not a gateway of this network")
end

return Proto
