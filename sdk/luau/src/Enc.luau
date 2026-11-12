--!strict
-- Base32 for IDs (RFC 4648, lower case, no padding), Base64url without padding and only in canonical form, hex.

local Errors = require("./Errors")

local Enc = {}

local B32 = "abcdefghijklmnopqrstuvwxyz234567"
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local B64_INDEX: { [number]: number } = {}
for i = 1, 64 do
	B64_INDEX[string.byte(B64, i)] = i - 1
end

function Enc.base32(data: string): string
	local out = table.create(math.ceil(#data * 8 / 5))
	local buffer, bits = 0, 0
	for i = 1, #data do
		buffer = (buffer * 256 + string.byte(data, i)) % 65536
		bits += 8
		while bits >= 5 do
			bits -= 5
			local index = math.floor(buffer / 2 ^ bits) % 32
			table.insert(out, string.sub(B32, index + 1, index + 1))
		end
	end
	if bits > 0 then
		local index = (buffer * 2 ^ (5 - bits)) % 32
		table.insert(out, string.sub(B32, index + 1, index + 1))
	end
	return table.concat(out)
end

function Enc.b64(data: string): string
	local out = table.create(math.ceil(#data / 3) * 4)
	for i = 1, #data, 3 do
		local a, b, c = string.byte(data, i, i + 2)
		local n = a * 65536 + (b or 0) * 256 + (c or 0)
		local count = if c then 4 elseif b then 3 else 2
		for k = 1, count do
			local index = math.floor(n / 2 ^ (18 - 6 * (k - 1))) % 64
			table.insert(out, string.sub(B64, index + 1, index + 1))
		end
	end
	return table.concat(out)
end

--- Decodes canonical Base64url (no padding, one spelling per value) of at most `maxBytes`.
function Enc.b64Var(text: any, field: string, maxBytes: number): string
	if type(text) ~= "string" then
		Errors.format(field .. ": not a string")
	end
	if #text > math.ceil(maxBytes / 3) * 4 + 4 then
		Errors.raise("TOO_LARGE", field)
	end
	if #text % 4 == 1 then
		Errors.format(field .. ": not base64url")
	end
	local out = table.create(#text)
	local buffer, bits = 0, 0
	for i = 1, #text do
		local value = B64_INDEX[string.byte(text, i)]
		if value == nil then
			Errors.format(field .. ": not base64url")
		end
		buffer = (buffer * 64 + value) % 16777216
		bits += 6
		if bits >= 8 then
			bits -= 8
			table.insert(out, string.char(math.floor(buffer / 2 ^ bits) % 256))
		end
	end
	local data = table.concat(out)
	if Enc.b64(data) ~= text then
		Errors.format(field .. ": not canonical base64url")
	end
	if #data > maxBytes then
		Errors.raise("TOO_LARGE", field)
	end
	return data
end

function Enc.b64Fixed(text: any, field: string, size: number): string
	local data = Enc.b64Var(text, field, size)
	if #data ~= size then
		Errors.format(field .. ": expected " .. size .. " bytes")
	end
	return data
end

function Enc.hex(data: string): string
	return (string.gsub(data, ".", function(c)
		return string.format("%02x", string.byte(c))
	end))
end

function Enc.fromHex(text: string): string
	return (string.gsub(text, "..", function(byte)
		return string.char(tonumber(byte, 16) :: number)
	end))
end

return Enc
