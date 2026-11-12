--!strict
-- What the SDK needs from its host: HTTP, the time, random bytes. `Bridge4.lune()` and `Bridge4.roblox()` fill it.

export type Response = { status: number, body: string }
export type Http = (method: string, url: string, headers: { [string]: string }, body: string?) -> Response

local Platform = {
	http = nil :: Http?,
	nowMs = function(): number
		return os.time() * 1000
	end,
}

return Platform
