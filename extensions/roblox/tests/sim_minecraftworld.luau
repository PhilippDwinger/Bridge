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
local workspaceRoot = Instance.new("Folder")
workspaceRoot.Name = "Workspace"

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
		local character, rootPart = makeCharacter(name)
		character.Parent = workspaceRoot
		self.Character = character
		self.rootPart = rootPart
	end
	return player
end

local modules = {}
local sources = {
	MinecraftWorldClient = "../examples/MinecraftWorld/Client.luau",
	PlayerSyncConfig = "../examples/MinecraftWorld/PlayerSyncConfig.luau",
}
local env
local function requireModule(name)
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
env = setmetatable({
	game = game, workspace = workspaceRoot, Instance = Instance, Vector3 = Vector3, CFrame = CFrame, Enum = Enum,
	Color3 = Color3, task = task, warn = warn,
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
		paddyLoads = paddy.loads, npcs = {} }
	if worldFolder then
		for _, chunk in ipairs(worldFolder:GetChildren()) do
			result.chunks += 1
			local info = { parts = 0, blocks = 0 }
			for _, part in ipairs(chunk:GetChildren()) do
				result.parts += 1
				info.parts += 1
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
			end
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
		local x = 1.5 + math.sin(t) * 3
		paddy.rootPart.CFrame = CFrame.new(Vector3.new(x, 15, 1.5))
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
		end
	end
	task.wait(1 / 30)
end
print("OBSERVATIONS " .. serde.encode("json", { observations = observations, requests = shim.requests,
	minutes = (os.clock() - started) / 60 }))
process.exit(0)
