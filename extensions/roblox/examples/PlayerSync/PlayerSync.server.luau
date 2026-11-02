--[[
	PlayerSync - test game for Bridge (Script in ServerScriptService)

	Every Roblox game server is ONE Bridge client. It publishes its players (position, direction, speed) several
	times per second to the topic "playersync" in the public realm of the Bridge server, and shows the players of
	every OTHER game server as NPCs. Two games (A and B) with this script: the players of A walk around in B as NPCs
	and the other way round.

	Needs in ServerStorage: the module "Bridge" and a ModuleScript "PlayerSyncConfig" (see config/A.luau).
	Also used by the MinecraftWorld game: there the players of Minecraft come in the same format (topic "playersync").
]]
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local ServerStorage = game:GetService("ServerStorage")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("PlayerSyncConfig"))

local TOPIC = Config.Topic or "playersync"
local SEND_RATE = Config.SendRate or 3 -- snapshots per second
local KEEPALIVE = 2 -- also send when nothing moved, at least this often (seconds)
local TIMEOUT = 6 -- a game server without a snapshot for this long is gone - its NPCs are removed
local OFFSET = Config.Offset or Vector3.zero
local LABEL = Config.Label or "?"
local IN_STUDIO = game.JobId == ""

local ANIMATIONS = { -- by rig type name
	R15 = {
		idle = "rbxassetid://507766388",
		walk = "rbxassetid://507777826",
		run = "rbxassetid://507767714",
		fall = "rbxassetid://507767968",
	},
	R6 = {
		idle = "rbxassetid://180435571",
		walk = "rbxassetid://180426354",
		run = "rbxassetid://180426354",
		fall = "rbxassetid://180436148",
	},
}

-- region Bridge client (everything about the connection is done by the module)
-- Config.Client: a client another script of this game already made (one Bridge client per game server), else our own
local client = Config.Client or Bridge.new({
	Server = Config.Server,
	Name = "PlayerSync " .. LABEL .. (if IN_STUDIO then " (Studio)" else " " .. string.sub(game.JobId, 1, 8)),
	-- Studio: always the same Bridge client (no new one per play test). Live servers: a new one per server that is
	-- deleted again when the server shuts down.
	IdentitySecret = if IN_STUDIO and Config.StudioSecret then Config.StudioSecret .. "-" .. LABEL else nil,
	-- 3 snapshots/s out + at most ~3 polls/s in = under 400 of the 500 HTTP requests per minute
	PollInterval = 0.3,
	Debug = Config.Debug == true,
})

client.Connected:Connect(function(clientIp)
	print("[PlayerSync " .. LABEL .. "] connected to Bridge as " .. clientIp)
end)
client.Disconnected:Connect(function(reason)
	warn("[PlayerSync " .. LABEL .. "] Bridge not reachable: " .. tostring(reason))
end)
client.ErrorOccurred:Connect(function(err)
	if Config.Debug then
		warn("[PlayerSync " .. LABEL .. "] " .. tostring(err))
	end
end)
-- endregion

-- region showing the players of the other game servers
local root = workspace:FindFirstChild("BridgeRemotePlayers") or Instance.new("Folder")
root.Name = "BridgeRemotePlayers"
root.Parent = workspace

local remoteServers = {} -- sender client IP -> {label, lastSeen, folder, npcs = {userId -> npc}}

local function round(value, step)
	return math.floor(value / step + 0.5) * step
end

local function steps(value, step) -- whole number of steps, for comparing snapshots
	return string.format("%.0f", value / step)
end

-- Newer Roblox versions call these ...Async, older ones without - use whichever exists
local function playersMethod(...)
	for _, name in ipairs({ ... }) do
		local ok, method = pcall(function()
			return (Players :: any)[name]
		end)
		if ok and type(method) == "function" then
			return method
		end
	end
	return nil
end
local createFromUserId = playersMethod("CreateHumanoidModelFromUserIdAsync", "CreateHumanoidModelFromUserId")
local createFromDescription = playersMethod("CreateHumanoidModelFromDescriptionAsync", "CreateHumanoidModelFromDescription")

local function buildModel(userId)
	local model = nil
	if userId > 0 and createFromUserId then
		local ok, result = pcall(createFromUserId, Players, userId)
		if ok then
			model = result
		end
	end
	if not model and createFromDescription then
		-- Studio test players (negative ids) or the avatar service is down: a default avatar
		local ok, result = pcall(createFromDescription, Players, Instance.new("HumanoidDescription"), Enum.HumanoidRigType.R15)
		if ok then
			model = result
		end
	end
	return model
end

local function destroyNpc(npc)
	npc.removed = true
	if npc.model then
		npc.model:Destroy()
		npc.model = nil
	end
end

local function removeServer(senderIp)
	local server = remoteServers[senderIp]
	if not server then
		return
	end
	remoteServers[senderIp] = nil
	for _, npc in pairs(server.npcs) do
		destroyNpc(npc)
	end
	server.folder:Destroy()
	print("[PlayerSync " .. LABEL .. "] game server " .. server.label .. " is gone")
end

local function setupModel(npc, model, server)
	local humanoid = model:FindFirstChildOfClass("Humanoid")
	local rootPart = model:FindFirstChild("HumanoidRootPart")
	if not humanoid or not rootPart then
		model:Destroy()
		return
	end
	for _, item in ipairs(model:GetDescendants()) do
		if item:IsA("BaseScript") then
			item:Destroy() -- no Animate / Health scripts: we move and animate the NPC ourselves
		elseif item:IsA("BasePart") then
			item.CanCollide = false
			item.CanTouch = false
			item.Anchored = false
		end
	end
	rootPart.Anchored = true
	model.Name = npc.name .. " [" .. server.label .. "]"
	humanoid.DisplayName = npc.display .. " · " .. server.label
	humanoid.DisplayDistanceType = Enum.HumanoidDisplayDistanceType.Viewer
	humanoid.HealthDisplayType = Enum.HumanoidHealthDisplayType.AlwaysOff
	pcall(function()
		humanoid.EvaluateStateMachine = false -- it is a puppet, no physics states
	end)
	rootPart.CFrame = npc.target or rootPart.CFrame
	npc.model = model -- from here on removing the NPC also removes the model
	npc.rootPart = rootPart
	model.Parent = server.folder

	local animator = humanoid:FindFirstChildOfClass("Animator") or Instance.new("Animator")
	animator.Parent = humanoid
	npc.tracks = {}
	for name, id in pairs(ANIMATIONS[humanoid.RigType.Name] or ANIMATIONS.R15) do
		local animation = Instance.new("Animation")
		animation.AnimationId = id
		local ok, track = pcall(function()
			return animator:LoadAnimation(animation)
		end)
		if ok and track then
			track.Looped = true
			npc.tracks[name] = track
		end
	end
end

local function createNpc(server, player)
	return {
		userId = player.u, name = tostring(player.n), display = tostring(player.d or player.n),
		anim = nil, removed = false, model = nil, rootPart = nil, tracks = {}, target = nil, speed = 0, air = false,
	}
end

-- Builds the avatar. Call it only when npc.target is set: for players without a Roblox avatar (e.g. from
-- Minecraft) the model can be there at once, without any yield.
local function buildNpc(server, npc, player)
	server.npcs[player.u] = npc
	task.spawn(function()
		local model = buildModel(player.u) -- yields (loads the avatar)
		if not model then
			return
		end
		if npc.removed or server.npcs[player.u] ~= npc or remoteServers[server.ip] ~= server then
			model:Destroy()
			return
		end
		setupModel(npc, model, server)
	end)
end

local function onSnapshot(data, event)
	if type(data) ~= "table" then
		return
	end
	if data.bye then
		removeServer(event.SenderIp)
		return
	end
	local server = remoteServers[event.SenderIp]
	if not server then
		local folder = Instance.new("Folder")
		folder.Name = "Server " .. tostring(data.label)
		folder.Parent = root
		server = { ip = event.SenderIp, label = tostring(data.label or "?"), folder = folder, npcs = {} }
		remoteServers[event.SenderIp] = server
		print("[PlayerSync " .. LABEL .. "] sees game server " .. server.label)
	end
	server.lastSeen = os.clock()
	local seen = {}
	for _, player in ipairs(data.players or {}) do
		if type(player) == "table" and type(player.u) == "number" and type(player.p) == "table" then
			seen[player.u] = true
			local npc = server.npcs[player.u]
			local isNew = npc == nil
			if isNew then
				npc = createNpc(server, player)
			end
			local position = Vector3.new(player.p[1] or 0, player.p[2] or 0, player.p[3] or 0) + OFFSET
			npc.target = CFrame.new(position) * CFrame.Angles(0, player.r or 0, 0)
			npc.speed = player.s or 0
			npc.air = player.a == true
			if isNew then
				buildNpc(server, npc, player)
			end
		end
	end
	for userId, npc in pairs(server.npcs) do
		if not seen[userId] then
			destroyNpc(npc)
			server.npcs[userId] = nil
		end
	end
end

local function animate(npc)
	local want = if npc.air then "fall" elseif npc.speed > 18 then "run" elseif npc.speed > 0.5 then "walk" else "idle"
	local track = npc.tracks[want]
	if want ~= npc.anim then
		local old = npc.anim and npc.tracks[npc.anim]
		if old then
			old:Stop(0.2)
		end
		if track then
			track:Play(0.2)
		end
		npc.anim = want
	end
	if track and (want == "walk" or want == "run") then
		track:AdjustSpeed(math.clamp(npc.speed / (if want == "run" then 24 else 14), 0.4, 2))
	end
end

RunService.Heartbeat:Connect(function(dt)
	local alpha = 1 - math.exp(-dt * 10)
	local now = os.clock()
	for senderIp, server in pairs(remoteServers) do
		if now - server.lastSeen > TIMEOUT then
			removeServer(senderIp)
		else
			for _, npc in pairs(server.npcs) do
				if npc.rootPart and npc.target then
					local current = npc.rootPart.CFrame
					if (current.Position - npc.target.Position).Magnitude > 40 then
						npc.rootPart.CFrame = npc.target -- teleported: jump there
					else
						npc.rootPart.CFrame = current:Lerp(npc.target, alpha) -- smooth between the snapshots
					end
					animate(npc)
				end
			end
		end
	end
end)

client:Subscribe(nil, TOPIC, onSnapshot)
-- endregion

-- region publishing the own players
local function snapshot()
	local list = {}
	local parts = {}
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local rootPart = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if rootPart and humanoid and humanoid.Health > 0 then
			local position = rootPart.Position
			local look = rootPart.CFrame.LookVector
			local velocity = rootPart.AssemblyLinearVelocity
			local entry = {
				u = player.UserId,
				n = player.Name,
				d = player.DisplayName,
				p = { round(position.X, 0.01), round(position.Y, 0.01), round(position.Z, 0.01) },
				r = round(math.atan2(-look.X, -look.Z), 0.001), -- yaw: CFrame.Angles(0, r, 0) looks the same way
				s = round(Vector3.new(velocity.X, 0, velocity.Z).Magnitude, 0.1),
				a = humanoid.FloorMaterial == Enum.Material.Air,
			}
			table.insert(list, entry)
			-- what counts as "moved": 5 cm, a few degrees, other speed / air state
			table.insert(parts, table.concat({ entry.u, steps(position.X, 0.05), steps(position.Y, 0.05),
				steps(position.Z, 0.05), steps(entry.r, 0.05), steps(entry.s, 0.5), tostring(entry.a) }, ":"))
		end
	end
	return list, table.concat(parts, "|")
end

client:BindToClose(function()
	-- the others remove our NPCs at once instead of after the timeout
	client:Publish(nil, TOPIC, { v = 1, label = LABEL, bye = true })
end)

task.spawn(function()
	local lastKey, lastSent = nil, 0
	while client.State ~= "destroyed" do
		task.wait(1 / SEND_RATE)
		local players, key = snapshot()
		if key ~= lastKey or os.clock() - lastSent >= KEEPALIVE then
			local ok, err = pcall(client.Publish, client, nil, TOPIC, { v = 1, label = LABEL, players = players })
			if ok then
				lastKey, lastSent = key, os.clock()
			elseif client.State ~= "destroyed" then
				warn("[PlayerSync " .. LABEL .. "] " .. tostring(err))
				task.wait(2)
			end
		end
	end
end)
-- endregion

print("[PlayerSync " .. LABEL .. "] started - Bridge server " .. client.Server)
