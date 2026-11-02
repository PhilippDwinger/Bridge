--[[
	Runs the REAL PlayerSync script outside Roblox: Lune's Roblox library gives real Instances / Vector3 / CFrame,
	this file fakes Players (moving test players), RunService.Heartbeat and ServerStorage. Two of these processes
	(game A + game B) against one real Bridge server check that each one shows the other one's players as NPCs.

	    lune run sim_playersync.luau <BridgeURL> <label> <scenario json>
]]
local shim = require("./roblox_shim")
local process = require("@lune/process")
local fs = require("@lune/fs")
local luau = require("@lune/luau")
local serde = require("@lune/serde")
local roblox = require("@lune/roblox")
local DateTime = require("@lune/datetime")
-- BRIDGE_SIM_MODULE / BRIDGE_SIM_SCRIPT: other versions of Bridge.luau / PlayerSync (to compare old and new)
local Bridge = if process.env.BRIDGE_SIM_MODULE then (require)(process.env.BRIDGE_SIM_MODULE) else require("../src/Bridge")

local URL, LABEL = process.args[1], process.args[2]
local scenario = serde.decode("json", process.args[3])

local function wall() -- seconds, the same clock for both game processes
	return DateTime.now().unixTimestampMillis / 1000
end
local Instance, Vector3, CFrame, Enum = roblox.Instance, roblox.Vector3, roblox.CFrame, roblox.Enum

-- region fake Roblox around the script
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
	rootPart.Parent = model
	local head = Instance.new("Part")
	head.Name = "Head"
	head.Parent = model
	local humanoid = Instance.new("Humanoid")
	-- Lune's Instances have no runtime values for these - set what a live character has
	humanoid.Health = 100
	humanoid.MaxHealth = 100
	humanoid.RigType = Enum.HumanoidRigType.R15
	humanoid.FloorMaterial = Enum.Material.Plastic
	rootPart.AssemblyLinearVelocity = Vector3.new(16, 0, 0)
	rootPart.CFrame = CFrame.new()
	rootPart.Position = Vector3.zero
	humanoid.Parent = model
	Instance.new("Animator").Parent = humanoid
	local animate = Instance.new("Script")
	animate.Name = "Animate"
	animate.Parent = model
	return model, rootPart
end

local testPlayers = {}
local avatarsBuilt = 0
local Players = {
	GetPlayers = function()
		local list = {}
		for _, player in ipairs(testPlayers) do
			table.insert(list, player)
		end
		return list
	end,
	CreateHumanoidModelFromUserIdAsync = function(_, userId)
		task.wait(0.2) -- loading an avatar takes a moment
		avatarsBuilt += 1
		return (makeCharacter("Avatar" .. userId))
	end,
	CreateHumanoidModelFromDescriptionAsync = function()
		avatarsBuilt += 1
		return (makeCharacter("Default"))
	end,
}
shim.services.Players = Players
local configs = {
	PlayerSyncConfig = { Server = URL, Label = LABEL, Topic = "playersync-sim", SendRate = 3, PollInterval = 0.15,
		Offset = Vector3.zero,
		StudioSecret = "simulated-studio-secret-0123456789abcdef", Debug = false },
}
shim.services.ServerStorage = {
	WaitForChild = function(_, name)
		return "module:" .. name
	end,
}

local env = setmetatable({
	game = game,
	workspace = workspaceRoot,
	Instance = Instance,
	Vector3 = Vector3,
	CFrame = CFrame,
	Enum = Enum,
	task = task,
	warn = warn,
	require = function(target)
		if target == "module:Bridge" then
			return Bridge
		end
		return configs[string.sub(target, 8)]
	end,
}, { __index = _G })
-- endregion

local function addPlayer(userId)
	local character, rootPart = makeCharacter("Player" .. userId)
	character.Parent = workspaceRoot
	table.insert(testPlayers, { UserId = userId, Name = "Player" .. userId, DisplayName = "Spieler" .. userId,
		Character = character, rootPart = rootPart })
end
for _, userId in ipairs(scenario.players) do
	addPlayer(userId)
end

local source = fs.readFile(process.env.BRIDGE_SIM_SCRIPT or "../examples/PlayerSync/PlayerSync.server.luau")
local script = luau.load(source, { debugName = "PlayerSync", environment = env })
task.spawn(script)

local function remoteFolder()
	return workspaceRoot:FindFirstChild("BridgeRemotePlayers")
end

local function observe()
	local folder = remoteFolder()
	local result = { servers = {}, npcs = 0, positions = {} }
	if folder then
		for _, serverFolder in ipairs(folder:GetChildren()) do
			local npcs = {}
			for _, model in ipairs(serverFolder:GetChildren()) do
				local humanoid = model:FindFirstChildOfClass("Humanoid")
				local rootPart = model:FindFirstChild("HumanoidRootPart")
				table.insert(npcs, {
					name = model.Name,
					display = humanoid and humanoid.DisplayName,
					anchored = rootPart and rootPart.Anchored,
					scripts = #(function()
						local found = {}
						for _, item in ipairs(model:GetDescendants()) do
							if item:IsA("BaseScript") then
								table.insert(found, item)
							end
						end
						return found
					end)(),
					x = rootPart and rootPart.CFrame.Position.X,
					z = rootPart and rootPart.CFrame.Position.Z,
					sneak = model:GetAttribute("McSneak"),
					userId = model:GetAttribute("McUserId"),
				})
			end
			result.servers[serverFolder.Name] = npcs
			result.npcs += #npcs
		end
	end
	return result
end

-- region simulation: players walk in circles (16 studs/s); heartbeat at 30 fps; scenario events at their times
local started = os.clock()
local startedWall = wall()
local observations = {}
local track = {} -- {wall time, NPC name, x, z} every frame while tracking (to measure how smooth / current it is)
local tracking = nil
local nextEvent = 1
local radius = 20
local lastFrame = os.clock()
while os.clock() - started < scenario.seconds do
	local t = wall() - startedWall
	for index, player in ipairs(testPlayers) do
		if process.env.BRIDGE_SIM_PATTERN == "zigzag" then
			-- back and forth on a line at 16 studs/s, turning round every 1.5 s (the hardest case for prediction)
			local phase = (t + index * 0.4) % 3
			local x = if phase < 1.5 then -12 + phase * 16 else 12 - (phase - 1.5) * 16
			player.rootPart.CFrame = CFrame.new(Vector3.new(x, 3, index * 6))
			player.rootPart.AssemblyLinearVelocity = Vector3.new(if phase < 1.5 then 16 else -16, 0, 0)
		else
			local angle = t * 0.8 + index
			player.rootPart.CFrame = CFrame.new(Vector3.new(math.cos(angle) * radius, 3, math.sin(angle) * radius))
				* CFrame.Angles(0, -angle, 0)
			player.rootPart.AssemblyLinearVelocity = Vector3.new(-math.sin(angle) * radius * 0.8, 0, math.cos(angle) * radius * 0.8)
		end
		player.rootPart.Position = player.rootPart.CFrame.Position -- Roblox derives it, Lune does not
	end
	local frame = os.clock()
	local frameWall = wall() -- the NPCs are placed for this moment
	for _, callback in ipairs(heartbeat) do
		callback(frame - lastFrame)
	end
	lastFrame = frame
	if tracking and t <= tracking then
		local folder = remoteFolder()
		for _, serverFolder in ipairs(folder and folder:GetChildren() or {}) do
			for _, model in ipairs(serverFolder:GetChildren()) do
				local rootPart = model:FindFirstChild("HumanoidRootPart")
				if rootPart then
					table.insert(track, { frameWall, model.Name, rootPart.CFrame.Position.X, rootPart.CFrame.Position.Z })
				end
			end
		end
	end
	local event = scenario.events[nextEvent]
	if event and t >= event.at then
		nextEvent += 1
		if event.action == "track" then
			tracking = event.at + event.seconds
		elseif event.action == "observe" then
			observations[event.name] = observe()
		elseif event.action == "sneak" then
			testPlayers[1].Character:SetAttribute("McSneak", true)
		elseif event.action == "leave" then
			for index, player in ipairs(testPlayers) do
				if player.UserId == event.userId then
					table.remove(testPlayers, index)
					player.Character:Destroy()
					break
				end
			end
		elseif event.action == "shutdown" then
			shim.close() -- game:BindToClose -> the script's "bye", then the client is destroyed
		end
	end
	task.wait(1 / 30)
end
-- endregion

print("OBSERVATIONS " .. serde.encode("json", { label = LABEL, observations = observations, avatars = avatarsBuilt,
	requests = shim.requests, minutes = (os.clock() - started) / 60, startedWall = startedWall, track = track,
	players = scenario.players }))
process.exit(0)
