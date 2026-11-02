--!nonstrict
--[[
	Bridge for Roblox  (ModuleScript "Bridge", server only)

	Connects a Roblox game server to a Bridge server and does all the work around it automatically:
	register / login, renewing the session before it runs out, logging in again (or registering again) after a
	Bridge restart, restoring realms / topics / commands after that, polling messages in the background (many per
	request), SHA-256 check of safe messages, unpacking compressed ones, staying under the HttpService limit
	(500 requests per minute per game server, shared by all clients of this module) and cleaning up on shutdown.

	    local Bridge = require(game:GetService("ServerStorage").Bridge)

	    local client = Bridge.new({ Server = "https://my-pc.tailnet.ts.net", Name = "Game A" })

	    client:Subscribe(nil, "chat", function(data, event)          -- nil = the public realm of the server
	        print(event.SenderIp, data.text)
	    end)
	    client:Publish(nil, "chat", { text = "Hello" })

	    client.MessageReceived:Connect(function(message)              -- direct messages
	        message:Reply({ got = message.Content })
	    end)
	    client:Send(otherClientIp, { hello = true })

	    client:HostCommand(nil, "add", function(args) return args.a + args.b end)
	    print(client:Call("add", { a = 1, b = 2 }))                   -- 3

	Every client is one Bridge client (one client IP). Create as many as you like: Bridge.new(...) again.
	Methods throw a readable error text ("[Bridge] ID: message (...)"); Bridge.ErrorId(err) returns the ID.
	Bridge never pushes - this module asks (long polling), exactly as Bridge's pull-only rule wants it.
]]

local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

local Bridge = {}
Bridge.VERSION = "1.0.0"
Bridge.ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>"

local POW2 = {}
for i = 0, 53 do
	POW2[i] = 2 ^ i
end

--------------------------------------------------------------------------------------------------------------------
-- region Signal
local Signal = {}
Signal.__index = Signal

function Signal.new()
	return setmetatable({ _handlers = {} }, Signal)
end

function Signal:Connect(callback)
	local handler = { callback = callback, connected = true }
	table.insert(self._handlers, handler)
	local signal = self
	local connection = { Connected = true }
	function connection.Disconnect()
		if not handler.connected then
			return
		end
		handler.connected = false
		connection.Connected = false
		local index = table.find(signal._handlers, handler)
		if index then
			table.remove(signal._handlers, index)
		end
	end
	return connection
end

function Signal:Once(callback)
	local connection
	connection = self:Connect(function(...)
		connection:Disconnect()
		callback(...)
	end)
	return connection
end

function Signal:Fire(...)
	for _, handler in ipairs(table.clone(self._handlers)) do
		if handler.connected then
			task.spawn(handler.callback, ...)
		end
	end
end

function Signal:Wait()
	local thread = coroutine.running()
	self:Once(function(...)
		task.spawn(thread, ...)
	end)
	return coroutine.yield()
end

function Signal:DisconnectAll()
	for _, handler in ipairs(self._handlers) do
		handler.connected = false
	end
	table.clear(self._handlers)
end

Bridge.Signal = Signal
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region errors
local BridgeError = {}
BridgeError.__index = BridgeError
BridgeError.__tostring = function(err)
	local where = err.Path or ""
	if err.Status and err.Status ~= 0 then
		where ..= " -> " .. tostring(err.Status)
	end
	return string.format("[Bridge] %s: %s%s", err.Id, tostring(err.Message or ""), where ~= "" and (" (" .. where .. ")") or "")
end

local function newError(id, message, status, path, details)
	return setmetatable({ Id = id, Message = message, Status = status, Path = path, Details = details }, BridgeError)
end

local function isError(value)
	return type(value) == "table" and getmetatable(value) == BridgeError
end

local function raise(id, message, status, path, details)
	error(newError(id, message, status, path, details), 0)
end

-- Errors after which trying again makes no sense (wrong setup) - the client stops and reports them
local FATAL = {
	HTTP_DISABLED = true,
	INVALID_CREDENTIALS = true,
	ALREADY_EXISTS = true,
	ARGUMENT_ERROR = true,
	DESTROYED = true,
	BRIDGE_URL_MISSING = true,
}

--- The error ID of an error thrown by this module ("SESSION_INVALID", "RECIPIENT_NOT_FOUND", ...) or nil.
function Bridge.ErrorId(err)
	if isError(err) then
		return err.Id
	end
	if type(err) == "string" then
		return string.match(err, "%[Bridge%] ([%w_]+):")
	end
	return nil
end

-- Public methods throw text (shows nicely in the output), internal code works with error objects.
local function public(method)
	return function(...)
		local results = table.pack(pcall(method, ...))
		if results[1] then
			return table.unpack(results, 2, results.n)
		end
		local err = results[2]
		error(if isError(err) then tostring(err) else err, 0)
	end
end
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region SHA-256 (for safe messages and stable identities)
local band, bor, bxor, bnot, rrotate, rshift, lshift =
	bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.rrotate, bit32.rshift, bit32.lshift
local MOD32 = 4294967296

local K256 = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

--- SHA-256 of a string (its bytes), as 64 lowercase hex characters.
local function sha256(message)
	local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local length = #message
	local zeros = (55 - length) % 64
	local bitLength = length * 8
	local high = math.floor(bitLength / MOD32)
	local low = bitLength % MOD32
	local padded = message
		.. "\128"
		.. string.rep("\0", zeros)
		.. string.char(
			math.floor(high / 16777216) % 256, math.floor(high / 65536) % 256, math.floor(high / 256) % 256, high % 256,
			math.floor(low / 16777216) % 256, math.floor(low / 65536) % 256, math.floor(low / 256) % 256, low % 256
		)
	local w = table.create(64, 0)
	for start = 1, #padded, 64 do
		for i = 0, 15 do
			local a, b, c, d = string.byte(padded, start + i * 4, start + i * 4 + 3)
			w[i] = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
		end
		for i = 16, 63 do
			local x, y = w[i - 15], w[i - 2]
			local s0 = bxor(rrotate(x, 7), rrotate(x, 18), rshift(x, 3))
			local s1 = bxor(rrotate(y, 17), rrotate(y, 19), rshift(y, 10))
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % MOD32
		end
		local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
		for i = 0, 63 do
			local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
			local ch = bxor(band(e, f), band(bnot(e), g))
			local t1 = (h + s1 + ch + K256[i + 1] + w[i]) % MOD32
			local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
			local maj = bxor(band(a, b), band(a, c), band(b, c))
			local t2 = (s0 + maj) % MOD32
			h, g, f, e, d, c, b, a = g, f, e, (d + t1) % MOD32, c, b, a, (t1 + t2) % MOD32
		end
		h0, h1, h2, h3 = (h0 + a) % MOD32, (h1 + b) % MOD32, (h2 + c) % MOD32, (h3 + d) % MOD32
		h4, h5, h6, h7 = (h4 + e) % MOD32, (h5 + f) % MOD32, (h6 + g) % MOD32, (h7 + h) % MOD32
	end
	return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7)
end
Bridge.Sha256 = sha256
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region Base64 + zlib inflate (for compressed messages)
local function bytesToString(bytes, count)
	local parts = {}
	for i = 1, count, 4096 do
		table.insert(parts, string.char(table.unpack(bytes, i, math.min(i + 4095, count))))
	end
	return table.concat(parts)
end

local B64_VALUE = {}
do
	local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i = 1, 64 do
		B64_VALUE[string.byte(alphabet, i)] = i - 1
	end
end

local function base64Decode(text)
	local out, count = {}, 0
	local bits, bitCount = 0, 0
	for i = 1, #text do
		local value = B64_VALUE[string.byte(text, i)]
		if value ~= nil then -- "=" and line breaks are skipped
			bits = bits * 64 + value
			bitCount += 6
			if bitCount >= 8 then
				bitCount -= 8
				local byte = math.floor(bits / POW2[bitCount])
				bits -= byte * POW2[bitCount]
				count += 1
				out[count] = byte
			end
		end
	end
	return bytesToString(out, count)
end
Bridge.Base64Decode = base64Decode

local LENGTH_BASE = { [0] = 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 }
local LENGTH_EXTRA = { [0] = 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 }
local DIST_BASE = { [0] = 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 }
local DIST_EXTRA = { [0] = 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 }
local CODE_LENGTH_ORDER = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 }

-- Canonical Huffman table (like zlib's puff.c): count per code length + symbols sorted by code
local function buildHuffman(lengths, offset, n)
	local count, symbol, offs = {}, {}, {}
	for len = 0, 15 do
		count[len] = 0
	end
	for s = 0, n - 1 do
		local len = lengths[offset + s] or 0
		count[len] += 1
	end
	offs[1] = 0
	for len = 1, 14 do
		offs[len + 1] = offs[len] + count[len]
	end
	for s = 0, n - 1 do
		local len = lengths[offset + s] or 0
		if len ~= 0 then
			symbol[offs[len]] = s
			offs[len] += 1
		end
	end
	return { count = count, symbol = symbol }
end

local FIXED_LIT, FIXED_DIST
local function fixedTables()
	if not FIXED_LIT then
		local lengths = {}
		for s = 0, 287 do
			lengths[s] = if s < 144 then 8 elseif s < 256 then 9 elseif s < 280 then 7 else 8
		end
		FIXED_LIT = buildHuffman(lengths, 0, 288)
		local dist = {}
		for s = 0, 29 do
			dist[s] = 5
		end
		FIXED_DIST = buildHuffman(dist, 0, 30)
	end
	return FIXED_LIT, FIXED_DIST
end

--- Unpacks zlib data (RFC 1950 + 1951). Errors on broken data.
local function inflateZlib(data)
	local size = #data
	local cmf, flg = string.byte(data, 1, 2)
	if not cmf or cmf % 16 ~= 8 or (cmf * 256 + flg) % 31 ~= 0 or math.floor(flg / 32) % 2 == 1 then
		error("inflate: no zlib data", 0)
	end
	local pos = 3
	local bitBuffer, bitCount = 0, 0
	local out, n = {}, 0

	local function bits(need)
		while bitCount < need do
			local byte = string.byte(data, pos)
			if byte == nil then
				error("inflate: data ends too early", 0)
			end
			pos += 1
			bitBuffer += byte * POW2[bitCount]
			bitCount += 8
		end
		local value = bitBuffer % POW2[need]
		bitBuffer = (bitBuffer - value) / POW2[need]
		bitCount -= need
		return value
	end

	local function decode(huffman)
		local code, first, index = 0, 0, 0
		local count, symbol = huffman.count, huffman.symbol
		for len = 1, 15 do
			code += bits(1)
			local c = count[len]
			if code - c < first then
				return symbol[index + code - first]
			end
			index += c
			first = (first + c) * 2
			code *= 2
		end
		error("inflate: invalid code", 0)
	end

	local function codes(lit, dist)
		while true do
			local sym = decode(lit)
			if sym < 256 then
				n += 1
				out[n] = sym
			elseif sym == 256 then
				return
			else
				sym -= 257
				if sym >= 29 then
					error("inflate: invalid length", 0)
				end
				local length = LENGTH_BASE[sym] + bits(LENGTH_EXTRA[sym])
				local dsym = decode(dist)
				if dsym >= 30 then
					error("inflate: invalid distance", 0)
				end
				local distance = DIST_BASE[dsym] + bits(DIST_EXTRA[dsym])
				if distance > n then
					error("inflate: distance too far back", 0)
				end
				for _ = 1, length do
					n += 1
					out[n] = out[n - distance]
				end
			end
		end
	end

	repeat
		local last = bits(1)
		local blockType = bits(2)
		if blockType == 0 then
			bitBuffer, bitCount = 0, 0 -- rest of the current byte is skipped
			local l1, l2, c1, c2 = string.byte(data, pos, pos + 3)
			if c2 == nil then
				error("inflate: data ends too early", 0)
			end
			pos += 4
			local length = l1 + l2 * 256
			if length ~= 65535 - (c1 + c2 * 256) then
				error("inflate: stored block length broken", 0)
			end
			if pos + length - 1 > size then
				error("inflate: data ends too early", 0)
			end
			for i = pos, pos + length - 1 do
				n += 1
				out[n] = string.byte(data, i)
			end
			pos += length
		elseif blockType == 1 then
			codes(fixedTables())
		elseif blockType == 2 then
			local nlen = bits(5) + 257
			local ndist = bits(5) + 1
			local ncode = bits(4) + 4
			local lengths = {}
			for i = 0, 18 do
				lengths[i] = 0
			end
			for i = 1, ncode do
				lengths[CODE_LENGTH_ORDER[i]] = bits(3)
			end
			local lencode = buildHuffman(lengths, 0, 19)
			local all, index = {}, 0
			while index < nlen + ndist do
				local sym = decode(lencode)
				if sym < 16 then
					all[index] = sym
					index += 1
				else
					local value, rep = 0, 0
					if sym == 16 then
						if index == 0 then
							error("inflate: repeat without length", 0)
						end
						value = all[index - 1]
						rep = 3 + bits(2)
					elseif sym == 17 then
						rep = 3 + bits(3)
					else
						rep = 11 + bits(7)
					end
					if index + rep > nlen + ndist then
						error("inflate: too many lengths", 0)
					end
					for _ = 1, rep do
						all[index] = value
						index += 1
					end
				end
			end
			codes(buildHuffman(all, 0, nlen), buildHuffman(all, nlen, ndist))
		else
			error("inflate: invalid block type", 0)
		end
	until last == 1
	return bytesToString(out, n)
end
Bridge.Inflate = inflateZlib
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region request budget (HttpService: 500 requests per minute per game server, for ALL scripts together)
local budget = { perMinute = 400, burst = 20, tokens = 20, last = os.clock(), used = 0 }

local function refill()
	local now = os.clock()
	budget.tokens = math.min(budget.burst, budget.tokens + (now - budget.last) * budget.perMinute / 60)
	budget.last = now
end

local function takeToken()
	refill()
	while budget.tokens < 1 do
		task.wait((1 - budget.tokens) * 60 / budget.perMinute)
		refill()
	end
	budget.tokens -= 1
	budget.used += 1
end

--- How many HTTP requests per minute all Bridge clients of this game server may use together (default 400 -
--- leaves 100 of Roblox's 500 for your other HttpService code). burst: how many may go out at once (default 20).
function Bridge.SetRequestBudget(perMinute, burst)
	assert(type(perMinute) == "number" and perMinute > 0, "perMinute must be a number > 0")
	refill()
	budget.perMinute = perMinute
	budget.burst = burst or math.clamp(math.floor(perMinute / 20), 1, 20)
	budget.tokens = math.min(budget.tokens, budget.burst)
end

function Bridge.GetRequestBudget()
	refill()
	return { PerMinute = budget.perMinute, Burst = budget.burst, Available = math.floor(budget.tokens), Used = budget.used }
end
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region HTTP
local function encodeJson(value, path)
	local ok, text = pcall(HttpService.JSONEncode, HttpService, value)
	if not ok then
		raise("ARGUMENT_ERROR", "Content cannot be sent as JSON (only numbers, text, booleans and tables; no Vector3, "
			.. "Instances, functions or mixed tables): " .. tostring(text), 0, path)
	end
	return text
end

--- One HTTP request. Returns status code and the decoded JSON (or nil). nullField: a key that is sent as JSON null.
local function rawRequest(method, url, body, path, nullField)
	local request = { Url = url, Method = method, Headers = { ["Content-Type"] = "application/json" } }
	if body ~= nil then
		local text = encodeJson(body, path)
		if nullField and body[nullField] == nil then
			text = string.sub(text, 1, -2) .. (if #text > 2 then "," else "") .. '"' .. nullField .. '":null}'
		end
		request.Body = text
	end
	takeToken()
	local ok, response = pcall(HttpService.RequestAsync, HttpService, request)
	if not ok then
		local text = tostring(response)
		local lower = string.lower(text)
		if string.find(lower, "not enabled", 1, true) then
			raise("HTTP_DISABLED", "HTTP requests are off. Studio: Home > Game Settings > Security > Allow HTTP Requests "
				.. "(or run game:GetService(\"HttpService\").HttpEnabled = true in the command bar)", 0, path)
		end
		if string.find(lower, "exceeded", 1, true) or string.find(lower, "too many", 1, true) then
			raise("RATE_LIMITED", "Roblox HttpService limit reached: " .. text, 0, path)
		end
		raise("UNREACHABLE", text, 0, path)
	end
	local data = nil
	if response.Body and #response.Body > 0 then
		local decoded, value = pcall(HttpService.JSONDecode, HttpService, response.Body)
		if decoded then
			data = value
		end
	end
	return response.StatusCode, data, response.Body
end

local function errorFromResponse(status, data, body, path)
	local detail = type(data) == "table" and data.detail or nil
	if type(detail) == "table" then
		local message = detail.message or ""
		local details = detail.details
		if type(details) == "table" and type(details.problems) == "table" and #details.problems > 0 then
			local problems = {}
			for _, problem in ipairs(details.problems) do
				table.insert(problems, tostring(problem))
			end
			message ..= " -> " .. table.concat(problems, "; ")
		end
		return newError(detail.error or "UNKNOWN_ERROR", message, status, path, details)
	end
	local text = if detail ~= nil then tostring(detail) else string.sub(tostring(body or ""), 1, 300)
	return newError("HTTP_" .. tostring(status), text, status, path)
end

local BRIDGE_ROUTES = {
	admin = true, server = true, s2s = true, client = true, message = true, command = true, realm = true,
	express = true, agent = true, conversation = true, friends = true,
}

--- "my-pc.ts.net/admin/" -> "https://my-pc.ts.net" (scheme added, Bridge paths like /admin cut, no trailing /)
local function normalizeServer(url)
	url = string.gsub(string.gsub(url, "^%s+", ""), "%s+$", "")
	if not string.find(url, "^https?://") then
		url = "https://" .. url
	end
	local scheme, host, path = string.match(url, "^(https?://)([^/%?#]+)([^%?#]*)")
	if not host then
		return url
	end
	if scheme == "https://" then
		host = string.gsub(host, ":443$", "")
	elseif scheme == "http://" then
		host = string.gsub(host, ":80$", "")
	end
	local kept = {}
	for segment in string.gmatch(path or "", "[^/]+") do
		if BRIDGE_ROUTES[string.lower(segment)] then
			break
		end
		table.insert(kept, segment)
	end
	return scheme .. string.lower(host) .. (if #kept > 0 then "/" .. table.concat(kept, "/") else "")
end
Bridge.NormalizeServer = normalizeServer

local function randomSecret()
	return string.gsub(HttpService:GenerateGUID(false) .. HttpService:GenerateGUID(false), "-", "")
end

local function jsonSize(value)
	local ok, text = pcall(HttpService.JSONEncode, HttpService, value)
	return if ok then #text else 0
end
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region Message / Task / Event objects
local Message = {}
Message.__index = Message

--- Answers a direct message (same conversation, causation = this message).
Message.Reply = public(function(self, content, options)
	options = table.clone(options or {})
	options.ConversationId = options.ConversationId or self.ConversationId
	options.CausationId = options.CausationId or self.Id
	return self.Client:_send(self.SenderIp, content, options)
end)

local Task = {}
Task.__index = Task

--- Answers the task (only once). Normally the return value of your HostCommand handler is sent for you.
Task.Respond = public(function(self, content, options)
	if self.Answered then
		raise("ALREADY_ANSWERED", "This task was answered already", 0, "/command/respond")
	end
	self.Answered = true
	options = options or {}
	return self.Client:_request("/command/respond", {
		task_id = self.Id,
		content = content,
		mode = self.Client:_pickMode(content, options.Mode),
	}, { nullField = "content" })
end)

--- Answers the task with an error. The caller's Call() then throws COMMAND_FAILED with this text.
Task.Fail = public(function(self, message)
	return self:Respond({ bridge_error = tostring(message) })
end)

--- Reports progress to the caller (only if the caller asked for it with Call(..., {Progress = "latest"})).
Task.Progress = public(function(self, percent, content)
	if not self.AcceptsProgress then
		return { delivered = false, reason = "caller_does_not_accept_progress" }
	end
	return self.Client:_request("/command/progress", { task_id = self.Id, percent = percent, content = content },
		{ nullField = "content" })
end)
-- endregion

--------------------------------------------------------------------------------------------------------------------
-- region Client
local Client = {}
Client.__index = Client
Bridge.Client = Client

local clients = {}
local closeBound = false

local DEFAULTS = {
	PollWait = 20, -- seconds a poll waits for something to arrive (long polling, Bridge allows up to 25)
	PollInterval = 0.25, -- at least this long between two polls (keeps the request budget)
	MaxMessages = 50, -- messages per poll request
	ConnectTimeout = 30, -- how long a call waits for the connection before it throws NOT_CONNECTED
	SessionMargin = 120, -- log in again this many seconds before the session runs out
	IgnoreOwnEvents = true, -- do not hand out events this client published itself
	AutoStart = true, -- connect right away in the background
	Receive = true, -- poll messages in the background
	Debug = false, -- print what happens
}

local function bindClose()
	if closeBound then
		return
	end
	closeBound = true
	pcall(function()
		game:BindToClose(function()
			Bridge.DestroyAll(10)
		end)
	end)
end

--[[
	Bridge.new(options) - creates a client. options:
	  Server         (required) URL of the Bridge server, e.g. "https://my-pc.tail1234.ts.net"
	  Name           name of the client (default "Roblox <JobId>")
	  Password       password of the client. Without Password/IdentitySecret/ClientIp the client is "ephemeral":
	                 a random password, a new client IP on every start and it is deleted again on shutdown.
	  IdentitySecret 32+ characters: always the SAME client IP on this server (also after a Bridge restart).
	                 The password is derived from it if you give none. Keep it secret (server scripts only).
	  ClientIp       log in to an existing client (with Password)
	  + PollWait, PollInterval, MaxMessages, ConnectTimeout, SessionMargin, IgnoreOwnEvents, AutoStart, Receive, Debug
]]
function Client.new(options)
	assert(type(options) == "table" and type(options.Server) == "string",
		'Bridge.new({ Server = "https://..." }) - Server is missing')
	if not RunService:IsServer() then
		error("[Bridge] Only usable on the server (a Script in ServerScriptService), not in LocalScripts", 2)
	end
	if options.IdentitySecret ~= nil and (type(options.IdentitySecret) ~= "string" or #options.IdentitySecret < 32) then
		error("[Bridge] IdentitySecret must be a text with at least 32 characters", 2)
	end
	local self = setmetatable({}, Client)
	for key, value in pairs(DEFAULTS) do
		self[key] = if options[key] ~= nil then options[key] else value
	end
	self.Server = normalizeServer(options.Server)
	local jobId = game.JobId
	self.Name = options.Name or ("Roblox " .. (if jobId ~= nil and jobId ~= "" then string.sub(jobId, 1, 8) else "Studio"))
	self._identity = options.IdentitySecret
	self._password = options.Password
		or (if self._identity then sha256("bridge-roblox-password|" .. self._identity) else nil)
		or randomSecret()
	self._ephemeral = if options.Ephemeral ~= nil
		then options.Ephemeral
		else (options.Password == nil and options.IdentitySecret == nil and options.ClientIp == nil)
	self.ClientIp = options.ClientIp
	self.ServerUrl = nil -- canonical URL the server gives itself (part of every address)
	self.PublicRealm = nil
	self.Limits = {}
	self.State = "idle" -- idle | connecting | connected | reconnecting | failed | destroyed
	self.Online = false
	self.LastError = nil

	self.Connected = Signal.new() -- (clientIp) connected / back online
	self.Disconnected = Signal.new() -- (reason) server not reachable any more
	self.ClientIpChanged = Signal.new() -- (newIp, oldIp) after a re-registration
	self.MessageReceived = Signal.new() -- (message) direct messages (and other plain messages)
	self.EventReceived = Signal.new() -- (event) every topic event (also the ones with a Subscribe handler)
	self.TaskReceived = Signal.new() -- (task) tasks for commands without a handler
	self.ResponseReceived = Signal.new() -- (response) responses no Call() waits for (Call with Async = true)
	self.ProgressReceived = Signal.new() -- (progress)
	self.ErrorOccurred = Signal.new() -- (errorObject) problems in the background

	self._topics = {} -- list of {realmRef, topic, handlers}
	self._commands = {} -- list of {realmRef, name, handler, options}
	self._realms = {} -- realm address -> join body (re-joined after a re-registration)
	self._waiters = {} -- task id -> waiting thread of Call()
	self._unclaimed = {} -- task id -> {response, at}: responses that came before their Call() was waiting
	self._syncCalls = 0
	self._closeHandlers = {}
	self._token = nil
	self._tokenExpires = 0
	self._connecting = false
	self._polling = false
	self._everConnected = false
	self._fatal = nil
	self._requests = 0

	table.insert(clients, self)
	bindClose()
	if self.AutoStart then
		task.spawn(self._connectLoop, self)
	end
	return self
end

function Bridge.new(options)
	return Client.new(options)
end

--- All clients of this game server.
function Bridge.GetClients()
	return table.clone(clients)
end

--- Destroys all clients (done automatically when the game server shuts down).
function Bridge.DestroyAll(timeout)
	local pending = 0
	for _, client in ipairs(table.clone(clients)) do
		pending += 1
		task.spawn(function()
			pcall(client.Destroy, client)
			pending -= 1
		end)
	end
	local deadline = os.clock() + (timeout or 10)
	while pending > 0 and os.clock() < deadline do
		task.wait(0.05)
	end
end

function Client:_log(...)
	if self.Debug then
		print("[Bridge:" .. self.Name .. "]", ...)
	end
end

function Client:_report(err)
	if not isError(err) then
		err = newError("SCRIPT_ERROR", tostring(err), 0, nil)
	end
	self.LastError = err
	self:_log("error:", tostring(err))
	self.ErrorOccurred:Fire(err)
end

function Client:_setOnline(online, reason)
	if self.Online == online then
		return
	end
	self.Online = online
	if online then
		self.Connected:Fire(self.ClientIp)
	else
		warn("[Bridge:" .. self.Name .. "] connection lost: " .. tostring(reason))
		self.Disconnected:Fire(reason)
	end
end

-- region connection
function Client:_waitForServer()
	local delay = 1
	local warned = false
	while true do
		if self.State == "destroyed" then
			raise("DESTROYED", "The client was destroyed", 0)
		end
		local ok, status, data = pcall(rawRequest, "GET", self.Server .. "/server/status", nil, "/server/status")
		if ok and status == 200 and type(data) == "table" and data.status ~= nil and type(data.url) ~= "string" then
			raise("BRIDGE_URL_MISSING", "The Bridge server has no public URL set - set it in BridgeControll", 0, "/server/status")
		elseif ok and status == 200 and type(data) == "table" and type(data.url) == "string" then
			if data.ready ~= false then
				return data
			end
			task.wait(0.5) -- the server restores its backup right now
		else
			if not ok and isError(status) and FATAL[status.Id] then
				error(status, 0)
			end
			local reason = if ok then ("answer " .. tostring(status)) else tostring(status)
			if not warned then
				warned = true
				warn("[Bridge:" .. self.Name .. "] " .. self.Server .. " not reachable (" .. reason .. ") - trying again")
			end
			self:_setOnline(false, reason)
			task.wait(delay)
			delay = math.min(delay * 2, 15)
		end
	end
end

function Client:_login()
	local data = self:_request("/client/login", { client_ip = self.ClientIp, password = self._password }, { auth = false })
	self._token = data.session_token
	self._tokenExpires = os.time() + math.floor((tonumber(data.remaining_minutes) or 60) * 60)
	self:_log("logged in, session for", data.remaining_minutes, "minutes")
end

function Client:_register()
	local body = { name = self.Name, password = self._password }
	if self._identity then
		body.identity_secret = self._identity
	end
	local ok, data = pcall(self._request, self, "/client/register", body, { auth = false })
	if not ok then
		if isError(data) and data.Id == "ALREADY_EXISTS" then
			data.Message = "This IdentitySecret is already used by a client with another password"
		end
		error(data, 0)
	end
	self.ClientIp = data.client_ip
	self:_log("registered as", self.ClientIp)
end

function Client:_doConnect()
	self.State = if self._everConnected then "reconnecting" else "connecting"
	local status = self:_waitForServer()
	self.ServerUrl = status.url
	self.PublicRealm = status.public_realm_address
	self.Limits = status.limits or {}
	if type(self.Limits.max_wait_seconds) == "number" then
		self.PollWait = math.min(self.PollWait, self.Limits.max_wait_seconds)
	end
	if type(self.Limits.max_poll_messages) == "number" then
		self.MaxMessages = math.min(self.MaxMessages, self.Limits.max_poll_messages)
	end

	local oldIp = self.ClientIp
	if self._identity then
		-- Same formula as the server: the IP of a stable identity is known before registering
		self.ClientIp = self.ServerUrl .. Bridge.ADDRESS_SPLIT
			.. string.sub(sha256("bridge-identity|" .. self.ServerUrl .. "|" .. self._identity), 1, 32)
	end
	if self.ClientIp then
		local ok, err = pcall(self._login, self)
		if not ok then
			local gone = isError(err) and err.Id == "INVALID_CREDENTIALS"
			if not (gone and (self._identity or self._ephemeral)) then
				error(err, 0)
			end
			-- The client does not exist (any more) on the server, e.g. Bridge restarted without backup: register again
			self:_log("client unknown on the server - registering again")
			self:_register()
			self:_login()
		end
	else
		self:_register()
		self:_login()
	end

	self.State = "connected"
	-- Realms / topics / commands this client should have (after a re-registration, or wished for before the first
	-- connection was there): set them up (again). Doing it twice does no harm.
	if next(self._realms) or #self._topics > 0 or #self._commands > 0 then
		self:_restore()
	end
	self._everConnected = true
	if oldIp and oldIp ~= self.ClientIp then
		self.ClientIpChanged:Fire(self.ClientIp, oldIp)
	end
	self:_setOnline(true)
	if self.Receive then
		task.spawn(self._pollLoop, self)
	end
end

function Client:_connectLoop()
	if self._connecting then
		return
	end
	self._connecting = true
	self._fatal = nil
	local delay = 1
	while self.State ~= "destroyed" do
		local ok, err = pcall(self._doConnect, self)
		if ok then
			break
		end
		if isError(err) and FATAL[err.Id] then
			if err.Id ~= "DESTROYED" then
				self._fatal = err
				self.State = "failed"
				warn(tostring(err))
				self:_report(err)
			end
			break
		end
		self:_report(err)
		task.wait(delay)
		delay = math.min(delay * 2, 15)
	end
	self._connecting = false
end

function Client:_ensureConnected(timeout)
	if self.State == "connected" then
		return
	end
	if self.State == "destroyed" or self._destroying then
		raise("DESTROYED", "The client was destroyed", 0)
	end
	if not self._connecting then
		if self.State == "failed" then
			self.State = "idle"
		end
		task.spawn(self._connectLoop, self)
	end
	local deadline = os.clock() + (timeout or self.ConnectTimeout)
	while self.State ~= "connected" do
		if self.State == "destroyed" then
			raise("DESTROYED", "The client was destroyed", 0)
		end
		if self._fatal and not self._connecting then
			error(self._fatal, 0)
		end
		if os.clock() > deadline then
			raise("NOT_CONNECTED", "No connection to " .. self.Server .. " (yet)", 0)
		end
		task.wait(0.05)
	end
end

function Client:_renewSession()
	if self._destroying then
		raise("DESTROYED", "The client is being destroyed", 0)
	end
	if self._renewing then
		while self._renewing do
			task.wait(0.05)
		end
		return
	end
	self._renewing = true
	local ok, err = pcall(self._login, self)
	self._renewing = false
	if ok then
		return
	end
	if isError(err) and err.Id == "INVALID_CREDENTIALS" and (self._identity or self._ephemeral) then
		-- The client is gone on the server: connect again from the start (register + restore)
		self._token = nil
		if self.State == "connected" then
			self.State = "reconnecting"
		end
		self:_ensureConnected(self.ConnectTimeout)
		return
	end
	error(err, 0)
end

--- One request to Bridge: waits for the connection, renews the session in time, logs in again on SESSION_INVALID,
--- waits while the server is starting. options: auth (default true), timeout (connection wait), nullField.
function Client:_request(path, body, options)
	options = options or {}
	local auth = options.auth ~= false
	body = body or {}
	local startingTries = 20
	local renewed = false
	while true do
		local token = nil
		if auth then
			self:_ensureConnected(options.timeout or self.ConnectTimeout)
			if os.time() >= self._tokenExpires - self.SessionMargin then
				self:_renewSession()
			end
			token = self._token
			body.session_token = token
			if options.realmRef ~= nil then
				body.realm_address = self:_resolveRealm(options.realmRef)
			end
		end
		self._requests += 1
		local status, data, text = rawRequest("POST", self.Server .. path, body, path, options.nullField)
		if status == 200 then
			return data
		end
		local err = errorFromResponse(status, data, text, path)
		if err.Id == "SERVER_STARTING" and startingTries > 0 then
			startingTries -= 1
			task.wait(0.5)
		elseif err.Id == "SESSION_INVALID" and auth and not renewed and not self._destroying and self.State ~= "destroyed" then
			renewed = true
			if self._token == token then
				self:_renewSession()
			end
		else
			error(err, 0)
		end
	end
end

-- After a re-registration (new client or Bridge lost its data): join the realms, subscribe the topics and host the
-- commands again. Already existing ones are fine.
function Client:_restore()
	for address, joinBody in pairs(self._realms) do
		local ok, err = pcall(self._request, self, "/realm/join", table.clone(joinBody))
		if not ok and not (isError(err) and err.Id == "ALREADY_EXISTS") then
			self:_report(err)
		end
	end
	for _, entry in ipairs(self._topics) do
		local ok, err = pcall(self._request, self, "/realm/topic/subscribe", { topic = entry.topic }, { realmRef = entry.realmRef })
		if not ok then
			self:_report(err)
		end
	end
	for _, entry in ipairs(self._commands) do
		local ok, err = pcall(self._createCommand, self, entry)
		if not ok and not (isError(err) and err.Id == "ALREADY_EXISTS") then
			self:_report(err)
		end
	end
	self:_log("restored", #self._topics, "topics,", #self._commands, "commands")
end
-- endregion

-- region receiving
function Client:_fetchChunked(item)
	local meta = item.message
	local pending = item.pending_id
	local ok, result = pcall(function()
		local chunks = {}
		for index = 0, (meta.chunk_count or 1) - 1 do
			local data = self:_request("/message/chunk", { pending_id = pending, chunk_index = index })
			chunks[index + 1] = data.chunk
		end
		local payload = table.concat(chunks)
		if meta.encoding == "zlib+base64" then
			payload = inflateZlib(base64Decode(payload))
		end
		local digest = sha256(payload)
		if digest ~= meta.sha256 then
			raise("HASH_MISMATCH", "Local SHA-256 check failed", 0, "/message/chunk")
		end
		self:_request("/message/complete", { pending_id = pending, sha256 = digest })
		return HttpService:JSONDecode(payload)
	end)
	if not ok then
		-- Give the message back, so it is not lost (it comes again with a later poll)
		pcall(self._request, self, "/message/cancel", { pending_id = pending })
		error(result, 0)
	end
	return result
end

function Client:_resolveRealm(realmRef)
	if realmRef == "public" then
		return self.PublicRealm
	end
	return realmRef
end

function Client:_findCommand(realmAddress, commandName)
	local byName = nil
	for _, entry in ipairs(self._commands) do
		if entry.name == commandName then
			if self:_resolveRealm(entry.realmRef) == realmAddress then
				return entry
			end
			byName = byName or entry
		end
	end
	return byName
end

function Client:_handleTask(meta, content)
	local job = setmetatable({
		Id = meta.message_id,
		Command = content.command_name,
		Args = content.command_args,
		Realm = content.realm_address,
		CallerIp = meta.sender_ip,
		AcceptsProgress = content.accepts_progress == true,
		Meta = meta,
		Client = self,
		Answered = false,
	}, Task)
	local entry = self:_findCommand(content.realm_address, content.command_name)
	if entry == nil then
		self.TaskReceived:Fire(job)
		return
	end
	task.spawn(function()
		local ok, result = pcall(entry.handler, job.Args, job)
		if job.Answered then
			return
		end
		local answered, err = pcall(if ok then job.Respond else job.Fail, job, result)
		if not answered then
			self:_report(err)
		end
	end)
end

function Client:_handleItem(item)
	local meta = item.message or {}
	local content = item.content
	if item.pending_id then
		content = self:_fetchChunked(item)
	end
	local kind = meta.content_type
	if kind == "event" then
		if self.IgnoreOwnEvents and meta.sender_ip == self.ClientIp then
			return
		end
		content = if type(content) == "table" then content else {}
		local event = {
			Realm = content.realm_address,
			Topic = content.topic,
			Data = content.data,
			SenderIp = meta.sender_ip,
			Meta = meta,
			Client = self,
		}
		for _, entry in ipairs(self._topics) do
			if entry.topic == event.Topic and self:_resolveRealm(entry.realmRef) == event.Realm then
				for _, handler in ipairs(table.clone(entry.handlers)) do
					task.spawn(function()
						local ok, err = pcall(handler, event.Data, event)
						if not ok then
							self:_report(newError("HANDLER_ERROR", "topic '" .. tostring(event.Topic) .. "': " .. tostring(err), 0))
						end
					end)
				end
			end
		end
		self.EventReceived:Fire(event)
	elseif kind == "task" then
		self:_handleTask(meta, type(content) == "table" and content or {})
	elseif kind == "response" then
		local response = { TaskId = meta.causation_id, Content = content, SenderIp = meta.sender_ip, Meta = meta }
		local taskId = response.TaskId
		local waiter = taskId and self._waiters[taskId]
		if waiter then
			self._waiters[taskId] = nil
			task.spawn(waiter, response)
		elseif taskId then
			-- A fast host can answer before /command/call has even returned the task id: keep it for that Call()
			local now = os.clock()
			for id, entry in pairs(self._unclaimed) do
				if now - entry.at > 120 then
					self._unclaimed[id] = nil
				end
			end
			self._unclaimed[taskId] = { response = response, at = now }
			local function hand_out()
				if self._unclaimed[taskId] then
					self._unclaimed[taskId] = nil
					self.ResponseReceived:Fire(response)
				end
			end
			if self._syncCalls > 0 then
				task.delay(1, hand_out) -- probably the answer of a running Call(): give it a moment to claim it
			else
				hand_out()
			end
		else
			self.ResponseReceived:Fire(response)
		end
	elseif kind == "progress" then
		self.ProgressReceived:Fire({ TaskId = meta.causation_id, Content = content, SenderIp = meta.sender_ip, Meta = meta })
	else
		self.MessageReceived:Fire(setmetatable({
			Id = meta.message_id,
			Type = kind,
			SenderIp = meta.sender_ip,
			Content = content,
			Mode = meta.mode,
			ConversationId = meta.conversation_id,
			Verified = meta.verified,
			Meta = meta,
			Client = self,
		}, Message))
	end
end

function Client:_pollLoop()
	if self._polling then
		return
	end
	self._polling = true
	local failures = 0
	while self.State ~= "destroyed" and self.Receive and not self._fatal do
		local started = os.clock()
		local ok, data = pcall(self._request, self, "/message/poll",
			{ wait_seconds = self.PollWait, max_messages = self.MaxMessages }, { timeout = math.huge })
		if self.State == "destroyed" then
			break
		end
		if ok then
			if failures > 0 then
				failures = 0
				self:_setOnline(true)
			end
			-- Older Bridge servers without max_messages answer with a single message
			local items = if type(data) ~= "table"
				then {}
				elseif type(data.messages) == "table" then data.messages
				elseif data.message ~= nil then { data }
				else {}
			for _, item in ipairs(items) do
				local handled, err = pcall(self._handleItem, self, item)
				if not handled then
					self:_report(err)
				end
			end
		else
			failures += 1
			if isError(data) and (data.Id == "UNREACHABLE" or string.sub(data.Id, 1, 5) == "HTTP_") then
				self:_setOnline(false, data.Message)
			end
			if not (isError(data) and data.Id == "DESTROYED") then
				self:_report(data)
			end
			task.wait(math.min(2 ^ math.min(failures, 4), 15))
		end
		local rest = self.PollInterval - (os.clock() - started)
		if rest > 0 then
			task.wait(rest)
		end
	end
	self._polling = false
end
-- endregion

-- region helpers for the public methods
function Client:_pickMode(content, mode)
	if mode ~= nil and mode ~= "auto" then
		return mode
	end
	local limit = (tonumber(self.Limits.max_fast_message_kib) or 64) * 1024 - 1024
	return if jsonSize(content) <= limit then "fast" else "safe"
end

-- nil / "public" -> "public" (the public realm of the server, looked up again after every connect), else the address
local function realmRefOf(realm)
	if realm == nil or realm == "public" then
		return "public"
	end
	assert(type(realm) == "string", "realm must be a realm address (text) or nil for the public realm")
	return realm
end

local function addTimes(body, options)
	body.expires_in_seconds = options.ExpiresInSeconds
	body.expires_at = options.ExpiresAt
	body.send_in_seconds = options.SendInSeconds
	body.send_at = options.SendAt
	body.timezone = options.Timezone
	body.if_past = options.IfPast
	return body
end

function Client:_send(recipientIp, content, options)
	options = options or {}
	assert(type(recipientIp) == "string", "recipientIp must be a client IP (text)")
	local mode = self:_pickMode(content, options.Mode)
	if mode == "temporary" and options.ExpiresInSeconds == nil and options.ExpiresAt == nil then
		options = table.clone(options)
		options.ExpiresInSeconds = 60
	end
	return self:_request("/message/send", addTimes({
		recipient_ip = recipientIp,
		content = content,
		mode = mode,
		conversation_id = options.ConversationId,
		causation_id = options.CausationId,
	}, options), { nullField = "content" })
end

function Client:_createCommand(entry)
	return self:_request("/realm/command/create", {
		command_name = entry.name,
		description = entry.options.Description,
		signature = entry.options.Signature,
		allowed_roles = entry.options.AllowedRoles,
	}, { realmRef = entry.realmRef })
end

local function isConnectionProblem(err)
	return isError(err) and (err.Id == "NOT_CONNECTED" or err.Id == "UNREACHABLE")
end
-- endregion

-- region public API
--- Starts connecting (only needed with AutoStart = false). Waits until connected (or timeout seconds).
Client.Connect = public(function(self, timeout)
	self:_ensureConnected(timeout or self.ConnectTimeout)
	return self.ClientIp
end)

--- Waits until the client is connected. Returns true, or false after timeout seconds.
function Client:WaitForConnection(timeout)
	return (pcall(self._ensureConnected, self, timeout or self.ConnectTimeout))
end

--- Sends a direct message. options: Mode ("auto" = fast if small, else safe | fast | safe | compressed | temporary),
--- ConversationId, CausationId, ExpiresInSeconds, SendInSeconds, ... Returns {message_id, ...}.
Client.Send = public(function(self, recipientIp, content, options)
	return self:_send(recipientIp, content, options)
end)

--- The same direct message to many clients at once.
Client.Broadcast = public(function(self, recipients, content, options)
	options = options or {}
	return self:_request("/message/broadcast", addTimes({
		recipients = recipients,
		content = content,
		mode = self:_pickMode(content, options.Mode),
		conversation_id = options.ConversationId,
	}, options), { nullField = "content" })
end)

--- Subscribes a topic of a realm (nil = public realm of the server). handler(data, event) gets every event.
--- Returns a subscription with :Disconnect() (unsubscribes on the server when the last handler is gone).
Client.Subscribe = public(function(self, realm, topic, handler)
	assert(type(topic) == "string", "topic must be a text")
	assert(type(handler) == "function", "handler must be a function(data, event)")
	local realmRef = realmRefOf(realm)
	local entry = nil
	for _, existing in ipairs(self._topics) do
		if existing.topic == topic and existing.realmRef == realmRef then
			entry = existing
		end
	end
	local subscription = { Topic = topic, Realm = realmRef }
	if entry then
		table.insert(entry.handlers, handler)
	else
		entry = { realmRef = realmRef, topic = topic, handlers = { handler } }
		table.insert(self._topics, entry)
		local ok, err = pcall(self._request, self, "/realm/topic/subscribe", { topic = topic }, { realmRef = realmRef })
		if not ok then
			if isConnectionProblem(err) then
				warn("[Bridge:" .. self.Name .. "] subscribe '" .. topic .. "' happens as soon as the server is reachable")
			else
				table.remove(self._topics, table.find(self._topics, entry))
				error(err, 0)
			end
		end
	end
	function subscription.Disconnect()
		local index = table.find(entry.handlers, handler)
		if not index then
			return
		end
		table.remove(entry.handlers, index)
		if #entry.handlers == 0 then
			table.remove(self._topics, table.find(self._topics, entry) or 0)
			pcall(self._request, self, "/realm/topic/unsubscribe", { topic = topic }, { realmRef = realmRef })
		end
	end
	subscription.Unsubscribe = subscription.Disconnect
	return subscription
end)

--- Publishes data to everybody who subscribed the topic (not back to yourself unless options.IncludeSelf).
--- options: Mode (default "auto" -> fast if small). Returns {subscribers, delivered, failed}.
Client.Publish = public(function(self, realm, topic, data, options)
	options = options or {}
	return self:_request("/realm/topic/publish", {
		topic = topic,
		content = data,
		mode = self:_pickMode(data, options.Mode),
		include_self = options.IncludeSelf == true,
	}, { nullField = "content", realmRef = realmRefOf(realm) })
end)

--- Hosts a command in a realm (nil = public realm). handler(args, task) returns the answer (or errors -> the caller
--- gets COMMAND_FAILED). options: Description, Signature (BridgeExpress), AllowedRoles. Returns {Remove = function}.
Client.HostCommand = public(function(self, realm, commandName, handler, options)
	assert(type(commandName) == "string", "commandName must be a text")
	assert(type(handler) == "function", "handler must be a function(args, task)")
	local realmRef = realmRefOf(realm)
	local entry = { realmRef = realmRef, name = commandName, handler = handler, options = options or {} }
	table.insert(self._commands, entry)
	local ok, err = pcall(self._createCommand, self, entry)
	if not ok and not (isError(err) and err.Id == "ALREADY_EXISTS") then
		if isConnectionProblem(err) then
			warn("[Bridge:" .. self.Name .. "] command '" .. commandName .. "' is hosted as soon as the server is reachable")
		else
			table.remove(self._commands, table.find(self._commands, entry))
			error(err, 0)
		end
	end
	local hosted = { Command = commandName }
	function hosted.Remove()
		local index = table.find(self._commands, entry)
		if index then
			table.remove(self._commands, index)
			pcall(self._request, self, "/realm/command/remove", { command_name = commandName }, { realmRef = realmRef })
		end
	end
	return hosted
end)

--- Calls a command and waits for the answer (returns it). options: Realm (address, default: all your realms),
--- Timeout (default 20 s), Mode, Strategy (least_busy | random | fastest), Progress (off | latest | all),
--- Async (true: do not wait, returns the task id - the answer comes as ResponseReceived).
Client.Call = public(function(self, commandName, args, options)
	options = options or {}
	if options.Async then
		return self:_call(commandName, args, options)
	end
	self._syncCalls += 1
	local ok, result = pcall(self._call, self, commandName, args, options)
	self._syncCalls -= 1
	if not ok then
		error(result, 0)
	end
	return result
end)

function Client:_call(commandName, args, options)
	local timeout = options.Timeout or 20
	local maxWait = tonumber(self.Limits.max_wait_seconds) or 25
	-- With the background poll the answer comes with the next poll (the server must not hold the call open then:
	-- the poll would take the answer away from it). Without it the server waits for the answer.
	local serverWait = if options.Async then 0
		elseif options.ServerWait ~= nil then math.min(timeout, options.ServerWait)
		elseif self.Receive then 0
		else math.min(timeout, maxWait)
	local started = os.clock()
	local result = self:_request("/command/call", {
		command_name = commandName,
		command_args = args,
		mode = self:_pickMode(args, options.Mode),
		strategy = options.Strategy or "least_busy",
		wait_seconds = serverWait,
		progress = options.Progress or "off",
	}, { realmRef = if options.Realm ~= nil then realmRefOf(options.Realm) else nil })
	if options.Async then
		return result.task_id
	end
	local response = result.response
	local early = self._unclaimed[result.task_id]
	if response == nil and early then
		self._unclaimed[result.task_id] = nil
		response = { content = early.response.Content }
	end
	if response == nil then
		-- Not answered yet: the answer comes with a later poll
		local remaining = timeout - (os.clock() - started)
		if remaining <= 0 or not self.Receive then
			raise("TIMEOUT", "'" .. commandName .. "' did not answer within " .. timeout .. " s", 0, "/command/call")
		end
		local thread = coroutine.running()
		self._waiters[result.task_id] = thread
		local timer = task.delay(remaining, function()
			if self._waiters[result.task_id] == thread then
				self._waiters[result.task_id] = nil
				task.spawn(thread, nil)
			end
		end)
		response = coroutine.yield()
		if response == nil then
			raise("TIMEOUT", "'" .. commandName .. "' did not answer within " .. timeout .. " s", 0, "/command/call")
		end
		pcall(task.cancel, timer)
		response = { content = response.Content }
	end
	local content = response.content
	if type(content) == "table" and content.bridge_error ~= nil then
		raise("COMMAND_FAILED", tostring(content.bridge_error), 0, "/command/call")
	end
	return content
end

--- The commands of a realm you may use.
Client.GetCommands = public(function(self, realm)
	return self:_request("/realm/commands", {}, { realmRef = realmRefOf(realm) }).commands
end)

--- Creates a realm ("public" | "protected" | "private"). options: AccessKey, RestrictedToOwner. Returns its address.
Client.CreateRealm = public(function(self, realmType, realmName, options)
	options = options or {}
	local data = self:_request("/realm/create", {
		realm_type = realmType,
		realm_name = realmName,
		access_key = options.AccessKey,
		restricted_to_owner = options.RestrictedToOwner,
	})
	return data.realm_address
end)

--- Joins a realm: JoinRealm(address) or JoinRealm({Realm = address, AccessKey = ...}) or JoinRealm({Code = "K7M3XQ9P",
--- ServerUrl = ...}). Returns the realm address. Joined realms are joined again after a re-registration.
Client.JoinRealm = public(function(self, spec)
	if type(spec) == "string" then
		spec = { Realm = spec }
	end
	local body = { realm_address = spec.Realm, access_key = spec.AccessKey, code = spec.Code, server_url = spec.ServerUrl }
	local data = self:_request("/realm/join", body)
	-- An invitation code works once - later joins use address + access key
	self._realms[data.realm_address] = { realm_address = data.realm_address, access_key = spec.AccessKey }
	return data.realm_address
end)

Client.LeaveRealm = public(function(self, realm)
	self._realms[realm] = nil
	return self:_request("/realm/leave", { realm_address = realm })
end)

Client.GetRealmInfo = public(function(self, realm)
	return self:_request("/realm/info", {}, { realmRef = realmRefOf(realm) })
end)

--- Invitation code for a realm you own. options: ExpiresInMinutes, MaxUses, Roles, PreferredCode.
Client.CreateCode = public(function(self, realm, options)
	options = options or {}
	return self:_request("/realm/code/create", {
		realm_address = realm,
		expires_in_minutes = options.ExpiresInMinutes,
		max_uses = options.MaxUses,
		roles = options.Roles,
		preferred_code = options.PreferredCode,
	}).code
end)

--- Information about this client (name, realms, ...).
Client.GetMe = public(function(self)
	return self:_request("/client/me", {})
end)

--- Who may send this client direct messages: mode "everyone" | "allowlist" | "nobody", allow / block: lists.
Client.SetDirectPolicy = public(function(self, mode, allow, block)
	return self:_request("/client/direct", { mode = mode, allow = allow, block = block })
end)

--- Any other Bridge endpoint: client:Request("/message/status", {message_id = id}). Session is added for you.
Client.Request = public(function(self, path, body)
	return self:_request(path, body or {})
end)

--- callback() runs at the start of Destroy() (also on game shutdown) while the client is still connected -
--- e.g. to publish a last "bye".
function Client:BindToClose(callback)
	table.insert(self._closeHandlers, callback)
end

--- Request statistics of this client.
function Client:GetStats()
	return { Requests = self._requests, State = self.State, Online = self.Online, ClientIp = self.ClientIp }
end

--- Stops the client and cleans up on the server: ephemeral clients are deleted, the others unsubscribe their topics,
--- remove their commands and log out. Called for every client automatically when the game server shuts down.
function Client:Destroy()
	if self.State == "destroyed" or self._destroying then
		return
	end
	self._destroying = true
	for _, callback in ipairs(self._closeHandlers) do
		local ok, err = pcall(callback)
		if not ok then
			warn("[Bridge:" .. self.Name .. "] BindToClose: " .. tostring(err))
		end
	end
	self.Receive = false
	if self.State == "connected" and self._token then
		local deleted = false
		if self._ephemeral then
			deleted = pcall(self._request, self, "/client/delete", { password = self._password }, { timeout = 0 })
		end
		if not deleted then
			for _, entry in ipairs(self._topics) do
				pcall(self._request, self, "/realm/topic/unsubscribe", { topic = entry.topic },
					{ timeout = 0, realmRef = entry.realmRef })
			end
			for _, entry in ipairs(self._commands) do
				pcall(self._request, self, "/realm/command/remove", { command_name = entry.name },
					{ timeout = 0, realmRef = entry.realmRef })
			end
			pcall(self._request, self, "/client/logout", {}, { timeout = 0 })
		end
	end
	self.State = "destroyed"
	self.Online = false
	self._token = nil
	for taskId, thread in pairs(self._waiters) do
		self._waiters[taskId] = nil
		task.spawn(thread, nil)
	end
	local index = table.find(clients, self)
	if index then
		table.remove(clients, index)
	end
	for _, signal in ipairs({ self.Connected, self.Disconnected, self.ClientIpChanged, self.MessageReceived,
		self.EventReceived, self.TaskReceived, self.ResponseReceived, self.ProgressReceived, self.ErrorOccurred }) do
		signal:DisconnectAll()
	end
	self._destroying = false
end
-- endregion
-- endregion

return Bridge
