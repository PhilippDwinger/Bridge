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
	-- Top / Bottom faces: how far their pictures are turned (0, 90, 180, 270) - Roblox does not document how a Texture lies
	-- there. Try it in the game with "/drehen oben 90" / "/drehen unten 180" (compare an observer's arrow or planks
	-- with Minecraft), then put the right numbers here
	TopTurn = 0,
	BottomTurn = 0,
	-- Real worlds: chunks around every Roblox player (Minecraft's "render distance"), and how many sections (16 blocks)
	-- below the lowest player still get built (caves deeper than that only when somebody goes down)
	ViewChunks = 5,
	SectionsBelow = 3,
	-- Milliseconds per frame the server may spend building blocks (more = loads faster, less = never stutters)
	BuildBudgetMs = 6,
	-- true: print what the Bridge module does
	Debug = false,
}
