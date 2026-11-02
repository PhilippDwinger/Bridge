--[[
	The ONE Bridge client of this game server (ModuleScript "MinecraftWorldClient" in ServerStorage).
	Both scripts - MinecraftWorld (the blocks) and PlayerSync (the players) - require it, so they share the client,
	its session and its HTTP budget (Roblox: 500 requests per minute per game server).
]]
local ServerStorage = game:GetService("ServerStorage")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))

local inStudio = game.JobId == ""

-- Nothing else in this game uses HttpService: the Bridge module may use 460 of Roblox's 500 requests per minute
Bridge.SetRequestBudget(460)

return Bridge.new({
	Server = Config.Server,
	Name = "MinecraftWorld " .. Config.Label .. (if inStudio then " (Studio)" else " " .. string.sub(game.JobId, 1, 8)),
	-- Studio: always the same client. Live servers: a new one per server, deleted again on shutdown.
	IdentitySecret = if inStudio and Config.StudioSecret then Config.StudioSecret .. "-world" else nil,
	-- one poll every 0.15 s: sends the newest own player state and fetches Minecraft's (players, blocks) in ONE
	-- request = 400 per minute, the rest of the budget is for loading chunks
	PollInterval = 0.15,
	Debug = Config.Debug == true,
})
