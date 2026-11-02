--[[
	Runs the REAL MinecraftWorld + PlayerSync scripts outside Roblox (Lune's Roblox library: real Instances, Vector3,
	CFrame; fake Players / RunService / ServerStorage) against a real Bridge server and a real Minecraft server with
	BridgeGameSync. Prints OBSERVATIONS as JSON for the test runner.

	    lune run sim_minecraftworld.luau <BridgeURL> <scenario json>
]]
local shim = require("./roblox_shim")
local process = require("@lune/process")
local fs = require("@lune/fs")
local luau = require("@lune/luau")
local serde = require("@lune/serde")
local roblox = require("@lune/roblox")
local Bridge = require("../src/Bridge")

local URL = process.args[1]
local scenario = serde.decode("json", process.args[2])
local Instance, Vector3, CFrame, Enum, Color3 = roblox.Instance, roblox.Vector3, roblox.CFrame, roblox.Enum, roblox.Color3

-- region fake Roblox
local heartbeat = {}
shim.services.RunService.Heartbeat = {
	Connect = function(_, callback)
		table.insert(heartbeat, callback)
		return { Disconnect = function() end }
	end,
}
local workspaceRoot = Instance.new("Workspace")
workspaceRoot.Name = "Workspace"
local starterPlayer = Instance.new("Folder")
starterPlayer.Name = "StarterPlayer"
local starterScripts = Instance.new("Folder")
starterScripts.Name = "StarterCharacterScripts"
starterScripts.Parent = starterPlayer
shim.services.StarterPlayer = starterPlayer
shim.services.KeyframeSequenceProvider = { RegisterKeyframeSequence = function()
	return "rbxassetid://0"
end }
local requireModule -- below

local function makeCharacter(name)
	local model = Instance.new("Model")
	model.Name = name
	local rootPart = Instance.new("Part")
	rootPart.Name = "HumanoidRootPart"
	rootPart.CFrame = CFrame.new()
	rootPart.Position = Vector3.zero
	rootPart.AssemblyLinearVelocity = Vector3.zero
	rootPart.Parent = model
	local humanoid = Instance.new("Humanoid")
	humanoid.Health = 100
	humanoid.MaxHealth = 100
	humanoid.RigType = Enum.HumanoidRigType.R15
	humanoid.FloorMaterial = Enum.Material.Plastic
	humanoid.Parent = model
	Instance.new("Animator").Parent = humanoid
	model.PrimaryPart = rootPart
	return model, rootPart
end

local playerAdded = {}
local testPlayers = {}
local Players = {
	CharacterAutoLoads = true,
	PlayerAdded = { Connect = function(_, callback) table.insert(playerAdded, callback) return { Disconnect = function() end } end },
	PlayerRemoving = { Connect = function() return { Disconnect = function() end } end },
	GetPlayers = function()
		return table.clone(testPlayers)
	end,
	CreateHumanoidModelFromUserIdAsync = function(_, userId)
		return (makeCharacter("Avatar" .. userId))
	end,
	CreateHumanoidModelFromDescriptionAsync = function()
		return (makeCharacter("DefaultAvatar"))
	end,
}
shim.services.Players = Players

local function newPlayer(userId, name)
	local player = { UserId = userId, Name = name, DisplayName = name, Character = nil, Parent = Players, loads = 0 }
	function player.LoadCharacter(self)
		self.loads += 1
		-- the game's StarterCharacter: a Minecraft character (MinecraftCharacter)
		local character = requireModule("MinecraftCharacter").build({ name = name })
		character:SetAttribute("McSkinUser", userId)
		character.Parent = workspaceRoot
		self.Character = character
		local rootPart = character:FindFirstChild("HumanoidRootPart")
		rootPart.Position = rootPart.CFrame.Position -- (Lune keeps Position apart from CFrame)
		rootPart.AssemblyLinearVelocity = Vector3.zero
		character:FindFirstChildOfClass("Humanoid").FloorMaterial = Enum.Material.Plastic
		self.rootPart = rootPart
	end
	return player
end

local modules = {}
local sources = {
	MinecraftWorldClient = "../examples/MinecraftWorld/Client.luau",
	PlayerSyncConfig = "../examples/MinecraftWorld/PlayerSyncConfig.luau",
	MinecraftCharacter = "../examples/MinecraftWorld/MinecraftCharacter.luau",
}
local env
function requireModule(name)
	if name == "Bridge" then
		return Bridge
	end
	if name == "MinecraftWorldConfig" then
		return { Server = URL, Label = "Roblox", WorldPrefix = "mcworld", PlayerTopic = "playersync", ChunksPerCall = 4,
			BlockColor = Color3.fromRGB(163, 162, 165), BlockMaterial = Enum.Material.SmoothPlastic,
			StudioSecret = "simulated-minecraftworld-secret-0123456789", Debug = false }
	end
	if modules[name] == nil then
		local chunk = luau.load(fs.readFile(sources[name]), { debugName = name, environment = env })
		modules[name] = chunk()
	end
	return modules[name]
end
shim.services.ServerStorage = {
	WaitForChild = function(_, name)
		return "module:" .. name
	end,
}

-- Remotes (Lune has no networking): plain tables that remember what the script connects and fires
local fired = { assetsChanged = 0, toClient = {}, toAll = {} }
local editHandler = nil
local fakeRemotes = {
	GetAssets = { Name = "GetAssets" },
	AssetsChanged = { Name = "AssetsChanged", FireAllClients = function()
		fired.assetsChanged += 1
	end },
	Edit = { Name = "Edit", OnServerEvent = { Connect = function(_, callback)
		editHandler = callback
		return { Disconnect = function() end }
	end } },
}
local handlers = {} -- remote name -> OnServerEvent handler
local remoteFolder = { Name = "MinecraftWorld", FindFirstChild = function(_, name)
	if not fakeRemotes[name] then
		-- any other remote (Move, Attack, Fall, Hurt): remembers its handler, firing to clients does nothing
		fakeRemotes[name] = { Name = name,
			FireClient = function(_, _player, ...)
				table.insert(fired.toClient, { name, ... })
			end,
			FireAllClients = function(_, ...)
				table.insert(fired.toAll, { name, ... })
			end,
			OnServerEvent = { Connect = function(_, callback)
				handlers[name] = callback
				return { Disconnect = function() end }
			end } }
	end
	return fakeRemotes[name]
end }
shim.services.ReplicatedStorage = {
	FindFirstChild = function(_, name)
		return if name == "MinecraftWorld" then remoteFolder else nil
	end,
	WaitForChild = function(_, name)
		return "module:" .. name
	end,
}
env = setmetatable({
	game = game, workspace = workspaceRoot, Instance = Instance, Vector3 = Vector3, CFrame = CFrame, Enum = Enum,
	Color3 = Color3, Vector2 = roblox.Vector2, task = task, warn = warn, buffer = buffer,
	require = function(target)
		return requireModule(string.sub(target, 8))
	end,
}, { __index = _G })
-- endregion

local function startScript(path, name)
	local script = luau.load(fs.readFile(path), { debugName = name, environment = env })
	task.spawn(script)
end

-- one Roblox player already in the game when the server starts
local paddy = newPlayer(4242, "RobloxPaddy")
table.insert(testPlayers, paddy)
startScript("../examples/MinecraftWorld/MinecraftWorld.server.luau", "MinecraftWorld")
startScript("../examples/PlayerSync/PlayerSync.server.luau", "PlayerSync")

local function find(parent, name)
	return parent and parent:FindFirstChild(name)
end

local function observe()
	local worldFolder = find(workspaceRoot, "MinecraftWorld")
	local result = { chunks = 0, parts = 0, sample = {}, perChunk = {}, spawn = nil, autoLoads = Players.CharacterAutoLoads,
		paddyLoads = paddy.loads, npcs = {}, grassParts = 0, textures = {}, assetsFired = fired.assetsChanged,
		partNames = {} }
	if worldFolder then
		for _, chunk in ipairs(worldFolder:GetChildren()) do
			result.chunks += 1
			local info = { parts = 0, blocks = 0 }
			for _, part in ipairs(chunk:GetChildren()) do
				result.parts += 1
				info.parts += 1
				result.partNames[part.Name] = (result.partNames[part.Name] or 0) + 1
				if part.Name == "minecraft:grass_block" then
					result.grassParts += 1
					if result.grassParts == 1 then
						for _, texture in ipairs(part:GetChildren()) do
							table.insert(result.textures, { texture.Face.Name, texture:GetAttribute("McTexture"),
								texture.StudsPerTileU, texture.StudsPerTileV })
						end
					end
				end
				local p, s = part.CFrame.Position, part.Size
				info.blocks += math.floor(s.X * s.Y * s.Z / 27 + 0.5)
				if chunk.Name == "Chunk 0,0" then
					table.insert(result.sample, { p.X, p.Y, p.Z, s.X, s.Y, s.Z })
				end
			end
			result.perChunk[chunk.Name] = info
		end
	end
	local spawn = find(workspaceRoot, "MinecraftSpawn")
	if spawn then
		local p = spawn.CFrame.Position
		result.spawn = { p.X, p.Y, p.Z }
	end
	local remote = find(workspaceRoot, "BridgeRemotePlayers")
	if remote then
		for _, serverFolder in ipairs(remote:GetChildren()) do
			for _, model in ipairs(serverFolder:GetChildren()) do
				table.insert(result.npcs, serverFolder.Name .. "/" .. model.Name)
				local root = model:FindFirstChild("HumanoidRootPart")
				local textures = 0
				for _, item in ipairs(model:GetDescendants()) do
					if item:IsA("Texture") and item:GetAttribute("McSkinFace") then
						textures += 1
					end
				end
				result.npc = { name = model.Name, skin = model:GetAttribute("McSkin"), slim = model:GetAttribute("McSlim"),
					skinUser = model:GetAttribute("McSkinUser"), rootY = root and root.CFrame.Position.Y, textures = textures,
					parts = #model:GetChildren(), pitch = model:GetAttribute("McPitch") }
			end
		end
	end
	if paddy.Character then
		result.paddy = { skin = paddy.Character:GetAttribute("McSkin"), slim = paddy.Character:GetAttribute("McSlim"),
			skinUser = paddy.Character:GetAttribute("McSkinUser") }
	end
	result.starterCharacter = starterPlayer:FindFirstChild("StarterCharacter") ~= nil
	result.animateBlocked = starterScripts:FindFirstChild("Animate") ~= nil
	result.gravity = workspaceRoot.Gravity
	result.toClient = fired.toClient
	result.toAll = {}
	for _, call in ipairs(fired.toAll) do
		if call[1] == "Chat" then
			table.insert(result.toAll, call)
		end
	end
	return result
end

local started = os.clock()
local observations = {}
local nextEvent = 1
while os.clock() - started < scenario.seconds do
	local t = os.clock() - started
	if paddy.rootPart then
		-- our player stands on the Minecraft spawn and walks a bit
		-- feet on the grass (Minecraft y -60 = 12 studs), the root part of a Minecraft character above
		local x = 1.5 + math.sin(t) * 3
		paddy.rootPart.CFrame = CFrame.new(Vector3.new(x, 12 + requireModule("MinecraftCharacter").ROOT_HEIGHT, 1.5))
		paddy.rootPart.Position = paddy.rootPart.CFrame.Position
	end
	for _, callback in ipairs(heartbeat) do
		callback(1 / 30)
	end
	local event = scenario.events[nextEvent]
	if event and t >= event.at then
		nextEvent += 1
		if event.action == "observe" then
			observations[event.name] = observe()
		elseif event.action == "assets" then
			-- what a client gets from GetAssets
			local payload = fakeRemotes.GetAssets.OnServerInvoke and fakeRemotes.GetAssets.OnServerInvoke(paddy)
			local sizes = {}
			for key, texture in pairs(payload and payload.textures or {}) do
				sizes[key] = { texture.w, texture.h, buffer.len(texture.pixels) }
			end
			observations[event.name] = { available = payload and payload.available, scale = payload and payload.scale,
				minY = payload and payload.minY, sizes = sizes, items = payload and payload.items, gui = payload and payload.gui,
				blocks = payload and payload.blocks }
		elseif event.action == "sneak" then
			paddy.Character:SetAttribute("McSneak", event.value == true)
		elseif event.action == "chat" then
			-- what the client sends when our player writes in the chat ("/..." = a Minecraft command)
			handlers.Chat(paddy, event.text)
		elseif event.action == "skin" then
			-- what a client asks for the pixels of a skin
			local key = (if event.npc then (observe().npc or {}).skin else paddy.Character:GetAttribute("McSkin"))
			local picture = fakeRemotes.GetSkin.OnServerInvoke and fakeRemotes.GetSkin.OnServerInvoke(paddy, key)
			observations[event.name] = { key = key, w = picture and picture.w, h = picture and picture.h,
				bytes = picture and buffer.len(picture.pixels) }
		elseif event.action == "edit" then
			-- a click of our player: the RemoteEvent from the client script
			editHandler(paddy, event.what, event.x, event.y, event.z, event.item)
			observations[event.name] = observe()
		end
	end
	task.wait(1 / 30)
end
print("OBSERVATIONS " .. serde.encode("json", { observations = observations, requests = shim.requests,
	minutes = (os.clock() - started) / 60 }))
process.exit(0)
