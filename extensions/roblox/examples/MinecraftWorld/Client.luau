--[[
	The ONE Bridge client of this game server (ModuleScript "MinecraftWorldClient" in ServerStorage).
	Both scripts - MinecraftWorld (the blocks) and PlayerSync (the players) - require it, so they share the client,
	its session and its HTTP budget (Roblox: 500 requests per minute per game server).
]]
local ServerStorage = game:GetService("ServerStorage")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))

local inStudio = game.JobId == ""

return Bridge.new({
	Server = Config.Server,
	Name = "MinecraftWorld " .. Config.Label .. (if inStudio then " (Studio)" else " " .. string.sub(game.JobId, 1, 8)),
	-- Studio: always the same client. Live servers: a new one per server, deleted again on shutdown.
	IdentitySecret = if inStudio and Config.StudioSecret then Config.StudioSecret .. "-world" else nil,
	-- player snapshots 3/s out + at most ~3 polls/s in = under 400 of the 500 HTTP requests per minute
	PollInterval = 0.3,
	Debug = Config.Debug == true,
})
