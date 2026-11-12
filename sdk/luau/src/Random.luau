--!strict
--[[
	Random bytes for keys, one-time keys and nonces (N1). Luau has no cryptographic random source, so the platform
	must give one: `Random.setEntropySource(fn)` with a function that returns fresh unpredictable bytes (Lune: the
	operating system's random; Roblox: GUIDs of HttpService, see Bridge4.roblox). Without a source every request for
	random bytes fails (fail closed). The bytes come from a ChaCha20 generator that is re-keyed after every request
	(forward secrecy) and mixed with new entropy every 32 requests.
]]

local Crypto = require("./Crypto")
local Errors = require("./Errors")

local Random = {}

local source: (() -> string)? = nil
local key: string? = nil
local counter = 0

function Random.setEntropySource(fn: () -> string)
	source = fn
	key = nil
end

function Random.hasEntropySource(): boolean
	return source ~= nil
end

local function reseed()
	local fresh = (source :: () -> string)()
	if type(fresh) ~= "string" or #fresh < 32 then
		Errors.raise("NO_ENTROPY", "the entropy source must give at least 32 bytes")
	end
	key = Crypto.sha256((key or "") .. fresh .. tostring(os.clock()) .. tostring({}))
	counter = 0
end

--- `n` random bytes (fails without an entropy source).
function Random.bytes(n: number): string
	if source == nil then
		Errors.raise("NO_ENTROPY", "no entropy source - Bridge4.lune() or Bridge4.roblox() sets one")
	end
	if key == nil or counter >= 32 then
		reseed()
	end
	counter += 1
	local nonce = string.pack("<I4I4I4", counter, 0, 0)
	local stream = Crypto.chacha20(key :: string, 0, nonce, string.rep("\0", n + 32))
	key = string.sub(stream, 1, 32)
	return string.sub(stream, 33)
end

return Random
