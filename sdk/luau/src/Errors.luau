--!strict
-- Errors of the Bridge 4 SDK: tables {code, message, retryAfter?, status?} raised with error(); codes as in docs/04 §9.

export type BridgeError = { code: string, message: string, retryAfter: number?, status: number? }

local Errors = {}

local meta = {
	__tostring = function(self: BridgeError): string
		return if self.message ~= "" then self.code .. ": " .. self.message else self.code
	end,
}

function Errors.new(code: string, message: string?, retryAfter: number?, status: number?): BridgeError
	return setmetatable({ code = code, message = message or "", retryAfter = retryAfter, status = status }, meta) :: any
end

function Errors.raise(code: string, message: string?): never
	error(Errors.new(code, message), 0)
end

function Errors.format(message: string): never
	error(Errors.new("BAD_FORMAT", message), 0)
end

function Errors.signature(): never
	error(Errors.new("BAD_SIGNATURE"), 0)
end

function Errors.untrusted(message: string): never
	error(Errors.new("UNTRUSTED", message), 0)
end

--- The code of an error value (a BridgeError, or "INTERNAL" for anything else).
function Errors.code(value: any): string
	return if type(value) == "table" and type(value.code) == "string" then value.code else "INTERNAL"
end

return Errors
