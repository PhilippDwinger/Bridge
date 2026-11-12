--!strict
--[[
	Strict JSON in, canonical JSON (RFC 8785) out - the rules of the Rust core (docs/04 §1, Z3): size first, UTF-8,
	no duplicate keys, integers within ±(2^53-1) only (no floats, no -0), depth at most 32, no lone surrogates.

	Values: objects and arrays are tables marked with `Json.object` / `Json.array` (the parser marks them), `Json.null`
	for null, strings are UTF-8 Luau strings, numbers are integers. A plain table without mark is written as an array
	if its keys are exactly 1..n, otherwise as an object (an empty plain table is an object).
]]

local Errors = require("./Errors")

local Json = {}

local OBJECT = { __json = "object" }
local ARRAY = { __json = "array" }
Json.null = setmetatable({}, { __tostring = function()
	return "null"
end })

Json.MAX_SAFE_INTEGER = 9007199254740991
Json.MAX_DEPTH = 32

function Json.object(t: { [any]: any }?): { [string]: any }
	return setmetatable(t or {}, OBJECT) :: any
end

function Json.array(t: { any }?): { any }
	return setmetatable(t or {}, ARRAY) :: any
end

function Json.isArray(value: any): boolean
	if type(value) ~= "table" or value == Json.null then
		return false
	end
	local mt = getmetatable(value)
	if mt == ARRAY then
		return true
	elseif mt == OBJECT then
		return false
	end
	local count = 0
	for key in value do
		if type(key) ~= "number" then
			return false
		end
		count += 1
	end
	return count > 0 and #value == count
end

function Json.isObject(value: any): boolean
	return type(value) == "table" and value ~= Json.null and not Json.isArray(value)
end

-- ---------------------------------------------------------------------------------------------------------------
-- parsing

local function fail(at: number, what: string): never
	Errors.format("json: " .. what .. " at " .. at)
end

local function utf8char(code: number): string
	return utf8.char(code)
end

local function parse(text: string, at: number, depth: number): (any, number)
	local function space(i: number): number
		while true do
			local c = string.byte(text, i)
			if c == 32 or c == 9 or c == 10 or c == 13 then
				i += 1
			else
				return i
			end
		end
	end

	local function str(i: number): (string, number)
		-- i points at the opening quote
		i += 1
		local parts = {}
		local start = i
		while true do
			local c = string.byte(text, i)
			if c == nil then
				fail(i, "unterminated string")
			elseif c == 34 then
				table.insert(parts, string.sub(text, start, i - 1))
				return table.concat(parts), i + 1
			elseif c < 32 then
				fail(i, "control character in string")
			elseif c == 92 then
				table.insert(parts, string.sub(text, start, i - 1))
				local e = string.byte(text, i + 1)
				local simple = ({ [34] = '"', [92] = "\\", [47] = "/", [98] = "\b", [102] = "\f", [110] = "\n", [114] = "\r", [116] = "\t" })[e or 0]
				if simple then
					table.insert(parts, simple)
					i += 2
				elseif e == 117 then
					local hex = string.sub(text, i + 2, i + 5)
					if not string.match(hex, "^%x%x%x%x$") then
						fail(i, "bad \\u escape")
					end
					local unit = tonumber(hex, 16) :: number
					i += 6
					if unit >= 0xD800 and unit <= 0xDBFF then
						local low = string.sub(text, i, i + 5)
						if not string.match(low, "^\\u%x%x%x%x$") then
							fail(i, "lone surrogate")
						end
						local second = tonumber(string.sub(low, 3), 16) :: number
						if second < 0xDC00 or second > 0xDFFF then
							fail(i, "lone surrogate")
						end
						table.insert(parts, utf8char(0x10000 + (unit - 0xD800) * 1024 + (second - 0xDC00)))
						i += 6
					elseif unit >= 0xDC00 and unit <= 0xDFFF then
						fail(i, "lone surrogate")
					else
						table.insert(parts, utf8char(unit))
					end
				else
					fail(i, "bad escape")
				end
				start = i
			else
				i += 1
			end
		end
	end

	at = space(at)
	local c = string.byte(text, at)
	if c == 123 then -- {
		if depth + 1 > Json.MAX_DEPTH then
			fail(at, "nesting deeper than 32")
		end
		local out = Json.object()
		at = space(at + 1)
		if string.byte(text, at) == 125 then
			return out, at + 1
		end
		while true do
			at = space(at)
			if string.byte(text, at) ~= 34 then
				fail(at, "key expected")
			end
			local key
			key, at = str(at)
			if rawget(out, key) ~= nil then
				fail(at, "duplicate key")
			end
			at = space(at)
			if string.byte(text, at) ~= 58 then
				fail(at, "colon expected")
			end
			local value
			value, at = parse(text, at + 1, depth + 1)
			out[key] = value
			at = space(at)
			local next = string.byte(text, at)
			at += 1
			if next == 125 then
				return out, at
			elseif next ~= 44 then
				fail(at, "comma expected")
			end
		end
	elseif c == 91 then -- [
		if depth + 1 > Json.MAX_DEPTH then
			fail(at, "nesting deeper than 32")
		end
		local out = Json.array()
		at = space(at + 1)
		if string.byte(text, at) == 93 then
			return out, at + 1
		end
		while true do
			local value
			value, at = parse(text, at, depth + 1)
			table.insert(out, value)
			at = space(at)
			local next = string.byte(text, at)
			at += 1
			if next == 93 then
				return out, at
			elseif next ~= 44 then
				fail(at, "comma expected")
			end
		end
	elseif c == 34 then
		return str(at)
	elseif c == 45 or (c and c >= 48 and c <= 57) then
		local token = string.match(text, "^%-?%d+", at) :: string?
		if not token or string.match(token, "^%-?0%d") then
			fail(at, "bad number")
		end
		local token_ = token :: string
		local next = string.byte(text, at + #token_)
		if next == 46 or next == 101 or next == 69 then
			fail(at, "floating point numbers are not allowed")
		end
		if token_ == "-0" then
			fail(at, "-0 is not allowed")
		end
		if #string.gsub(token_, "%-", "") > 16 then
			fail(at, "integer outside ±(2^53-1)")
		end
		local value = tonumber(token_) :: number
		if math.abs(value) > Json.MAX_SAFE_INTEGER then
			fail(at, "integer outside ±(2^53-1)")
		end
		return value, at + #token_
	elseif string.sub(text, at, at + 3) == "true" then
		return true, at + 4
	elseif string.sub(text, at, at + 4) == "false" then
		return false, at + 5
	elseif string.sub(text, at, at + 3) == "null" then
		return Json.null, at + 4
	end
	return fail(at, "unexpected character")
end

--- Parses `text` (bytes) as strict Bridge JSON; `maxBytes` is checked first.
function Json.parse(text: string, maxBytes: number): any
	if #text > maxBytes then
		Errors.raise("TOO_LARGE", "json over " .. maxBytes .. " bytes")
	end
	if utf8.len(text) == nil then
		Errors.format("not UTF-8")
	end
	if string.sub(text, 1, 3) == "\239\187\191" then
		Errors.format("json: byte order mark")
	end
	local value, at = parse(text, 1, 0)
	local rest = string.match(text, "^[ \t\r\n]*", at) :: string
	if at + #rest <= #text then
		fail(at, "trailing characters")
	end
	return value
end

-- ---------------------------------------------------------------------------------------------------------------
-- canonical writing

local function utf16Units(s: string): { number }
	local units = {}
	for _, code in utf8.codes(s) do
		if code >= 0x10000 then
			code -= 0x10000
			table.insert(units, 0xD800 + math.floor(code / 1024))
			table.insert(units, 0xDC00 + code % 1024)
		else
			table.insert(units, code)
		end
	end
	return units
end

local function before(a: string, b: string): boolean
	local ua, ub = utf16Units(a), utf16Units(b)
	for i = 1, math.min(#ua, #ub) do
		if ua[i] ~= ub[i] then
			return ua[i] < ub[i]
		end
	end
	return #ua < #ub
end

local function escape(s: string, out: { string })
	if utf8.len(s) == nil then
		Errors.format("not UTF-8")
	end
	table.insert(out, '"')
	table.insert(out, (string.gsub(s, '[%z\1-\31"\\]', function(c: string): string
		local byte = string.byte(c)
		if c == '"' then
			return '\\"'
		elseif c == "\\" then
			return "\\\\"
		elseif byte == 8 then
			return "\\b"
		elseif byte == 12 then
			return "\\f"
		elseif byte == 10 then
			return "\\n"
		elseif byte == 13 then
			return "\\r"
		elseif byte == 9 then
			return "\\t"
		end
		return string.format("\\u%04x", byte)
	end)))
	table.insert(out, '"')
end

local function write(value: any, out: { string }, depth: number)
	if depth > Json.MAX_DEPTH then
		Errors.format("nesting too deep")
	end
	local kind = type(value)
	if value == Json.null or value == nil then
		table.insert(out, "null")
	elseif kind == "boolean" then
		table.insert(out, if value then "true" else "false")
	elseif kind == "number" then
		if value ~= math.floor(value) or math.abs(value) > Json.MAX_SAFE_INTEGER then
			Errors.format("only integers within ±(2^53-1) are allowed")
		end
		table.insert(out, string.format("%d", value))
	elseif kind == "string" then
		escape(value, out)
	elseif kind == "table" then
		if Json.isArray(value) then
			table.insert(out, "[")
			for i, item in ipairs(value) do
				if i > 1 then
					table.insert(out, ",")
				end
				write(item, out, depth + 1)
			end
			table.insert(out, "]")
		else
			local keys = {}
			for key in value do
				if type(key) ~= "string" then
					Errors.format("object keys must be strings")
				end
				table.insert(keys, key)
			end
			table.sort(keys, before)
			table.insert(out, "{")
			for i, key in keys do
				if i > 1 then
					table.insert(out, ",")
				end
				escape(key, out)
				table.insert(out, ":")
				write(value[key], out, depth + 1)
			end
			table.insert(out, "}")
		end
	else
		Errors.format("not a JSON value: " .. kind)
	end
end

--- Canonical JSON bytes of a strict Bridge value.
function Json.canonical(value: any): string
	local out = {}
	write(value, out, 0)
	return table.concat(out)
end

--- Canonical bytes of an object without some keys.
function Json.canonicalWithout(object: { [string]: any }, skip: { string }): string
	local copy = Json.object()
	for key, value in object do
		if not table.find(skip, key) then
			copy[key] = value
		end
	end
	return Json.canonical(copy)
end

--- A shallow copy of an object (keeps the mark).
function Json.copy(object: { [string]: any }): { [string]: any }
	local copy = Json.object()
	for key, value in object do
		copy[key] = value
	end
	return copy
end

function Json.depth(value: any): number
	if type(value) ~= "table" or value == Json.null then
		return 0
	end
	local deepest = 0
	for _, child in value do
		deepest = math.max(deepest, Json.depth(child))
		if deepest > Json.MAX_DEPTH then
			break
		end
	end
	return deepest + 1
end

return Json
