-- PlayerSync settings in the MinecraftWorld game  (ModuleScript "PlayerSyncConfig" in ServerStorage)
-- Uses the shared client and the same coordinates as the blocks (no offset): Minecraft players walk on the blocks.
-- The Minecraft players are Minecraft characters (MinecraftCharacter) with Minecraft's animations; MinecraftWorld
-- gives them their skin (attribute McSkinUser = their id).
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")

local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))
-- (missing = Rojo still serves an older project: restart "rojo serve" and connect the plugin again)
local characterModule = ReplicatedStorage:WaitForChild("MinecraftCharacter", 15)
if not characterModule then
	error("[MinecraftWorld] ReplicatedStorage.MinecraftCharacter fehlt - Rojo neu starten: "
		.. "rojo serve minecraft-world.project.json --port 34874, dann im Rojo-Plugin neu verbinden")
end
local Character = require(characterModule :: any)

return {
	Client = require(ServerStorage:WaitForChild("MinecraftWorldClient")),
	Server = Config.Server,
	StudioSecret = Config.StudioSecret,
	Label = Config.Label,
	Topic = Config.PlayerTopic,
	Offset = Vector3.zero,
	Debug = Config.Debug,
	BuildModel = function(player)
		local model = Character.build({ name = tostring(player.n) })
		model:SetAttribute("McSkinUser", player.u)
		return model
	end,
	Animate = function(model)
		return Character.animate(model)
	end,
	OnHurt = function(model)
		Character.flashRed(model)
	end,
}
