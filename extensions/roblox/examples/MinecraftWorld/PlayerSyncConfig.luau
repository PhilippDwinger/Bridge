-- PlayerSync settings in the MinecraftWorld game  (ModuleScript "PlayerSyncConfig" in ServerStorage)
-- Uses the shared client and the same coordinates as the blocks (no offset): Minecraft players walk on the blocks.
local ServerStorage = game:GetService("ServerStorage")

local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))

return {
	Client = require(ServerStorage:WaitForChild("MinecraftWorldClient")),
	Server = Config.Server,
	StudioSecret = Config.StudioSecret,
	Label = Config.Label,
	Topic = Config.PlayerTopic,
	SendRate = 3,
	Offset = Vector3.zero,
	Debug = Config.Debug,
}
