-- PlayerSync settings of game A  (ModuleScript "PlayerSyncConfig" in ServerStorage)
return {
	-- The Bridge server "Roblox-Game-Sync" in BridgeControll (Tailscale Funnel, port 443)
	Server = "https://muttchen.tail91b057.ts.net",
	-- Shown at the NPCs in the OTHER game ("Paddy · A")
	Label = "A",
	-- Both games must use the same topic
	Topic = "playersync",
	-- Snapshots per second. 3 + the polling stays far below Roblox's 500 HTTP requests per minute.
	SendRate = 3,
	-- Moves the NPCs of the other game (e.g. Vector3.new(0, 0, 60) to put them next to your own map)
	Offset = Vector3.new(0, 0, 0),
	-- Studio only: always the same Bridge client instead of a new one per play test (32+ characters)
	StudioSecret = "psKuKT2s2phc-nBs6x8igTQpgpLUvQ_02UDkw4Is",
	-- true: print what the Bridge module does
	Debug = false,
}
