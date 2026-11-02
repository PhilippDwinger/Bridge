-- MinecraftWorld settings  (ModuleScript "MinecraftWorldConfig" in ServerStorage)
return {
	-- The Bridge server "Roblox-Game-Sync" in BridgeControll (Tailscale Funnel, port 443) - the Minecraft mod uses it too
	Server = "https://muttchen.tail91b057.ts.net",
	-- Shown at the Roblox players in Minecraft ("Paddy · Roblox")
	Label = "Roblox",
	-- Must match "worldPrefix" / "playerTopic" in Minecraft's config/bridgegamesync.json
	WorldPrefix = "mcworld",
	PlayerTopic = "playersync",
	-- Chunks per request while loading (a chunk of a flat world is tiny, a normal one bigger)
	ChunksPerCall = 4,
	-- Placeholder look of every Minecraft block for now
	BlockColor = Color3.fromRGB(163, 162, 165),
	BlockMaterial = Enum.Material.SmoothPlastic,
	-- Studio only: always the same Bridge client instead of a new one per play test (32+ characters)
	StudioSecret = "2RavZ4TSU65j2ha0whUno65Q7c689arhMk74Szx2",
	-- true: print what the Bridge module does
	Debug = false,
}
