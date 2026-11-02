--[[
	PlayerSync - test game for Bridge (Script in ServerScriptService)

	Every Roblox game server is ONE Bridge client. It publishes its players (position, velocity, direction) to the
	topic "playersync" in the public realm of the Bridge server, and shows the players of every OTHER game server as
	NPCs. Two games (A and B) with this script: the players of A walk around in B as NPCs and the other way round.

	Smooth and always current:
	- Only the NEWEST state goes out (PublishLatest): it travels with every poll, ~7 times per second, in the same
	  request that fetches the others' states - so it stays under Roblox's 500 HTTP requests per minute.
	- Only the NEWEST state is shown (Subscribe Latest + time stamps): older snapshots are skipped, never replayed.
	- Between two snapshots the NPCs keep moving with the sent velocity (prediction, at most MAX_PREDICT seconds),
	  differences are smoothed away within SMOOTH seconds - no stop-and-go.

	Needs in ServerStorage: the module "Bridge" and a ModuleScript "PlayerSyncConfig" (see config/A.luau).
	Also used by the MinecraftWorld game: there the players of Minecraft come in the same format (topic "playersync").
]]
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local ServerStorage = game:GetService("ServerStorage")
local HttpService = game:GetService("HttpService")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("PlayerSyncConfig"))

local TOPIC = Config.Topic or "playersync"
local SAMPLE_RATE = Config.SampleRate or 20 -- the own players are measured this often; the newest goes out with each poll
local KEEPALIVE = 2 -- also send when nothing moved, at least this often (seconds)
local TIMEOUT = 6 -- a game server without a snapshot for this long is gone - its NPCs are removed
local OFFSET = Config.Offset or Vector3.zero
local LABEL = Config.Label or "?"
local IN_STUDIO = game.JobId == ""
local MAX_PREDICT = 0.35 -- seconds an NPC keeps moving with the last velocity (a later snapshot is late - it waits)
local SMOOTH = 0.1 -- seconds in which a difference to a new snapshot is smoothed away
local TELEPORT = 40 -- studs: a bigger difference is a teleport - jump there
local DRIFT = 0.002 -- seconds per second the clock comparison may drift (two computers' clocks never run exactly alike)
local SESSION = HttpService:GenerateGUID(false) -- this run of the script: the others know which snapshots belong together

local ANIMATIONS = { -- by rig type name
	R15 = {
		idle = "rbxassetid://507766388",
		walk = "rbxassetid://507777826",
		run = "rbxassetid://507767714",
		fall = "rbxassetid://507767968",
		slash = "rbxassetid://522635514", -- swinging the arm (hit / build)
	},
	R6 = {
		idle = "rbxassetid://180435571",
		walk = "rbxassetid://180426354",
		run = "rbxassetid://180426354",
		fall = "rbxassetid://180436148",
		slash = "rbxassetid://129967390",
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
	-- one poll every 0.15 s (sends the newest own state and fetches the others') = 400 HTTP requests per minute
	PollInterval = Config.PollInterval or 0.15,
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

local remoteServers = {} -- sender client IP -> {label, lastSeen, folder, npcs = {userId -> npc}, sid, lastT, offset}
local goodbyes = {} -- sender client IP -> session that said "bye" (its late snapshots must not bring the NPCs back)

local function round(value, step)
	return math.floor(value / step + 0.5) * step
end

local function steps(value, step) -- whole number of steps, for comparing snapshots
	return string.format("%.0f", value / step)
end

local function vector(list, fallback)
	if type(list) ~= "table" then
		return fallback
	end
	return Vector3.new(tonumber(list[1]) or 0, tonumber(list[2]) or 0, tonumber(list[3]) or 0)
end

-- Where the NPC is NOW: the last snapshot carried forward with its velocity (and gravity in the air)
local function predict(npc, now)
	local age = math.clamp(now - npc.sampleAt, 0, MAX_PREDICT)
	local w = npc.velocity
	local y = npc.position.Y + w.Y * age
	if npc.air then
		y -= 0.5 * npc.gravity * age * age
	end
	return Vector3.new(npc.position.X + w.X * age, y, npc.position.Z + w.Z * age)
end

local function turnTowards(current, target, alpha) -- shortest way round
	local difference = (target - current + math.pi) % (2 * math.pi) - math.pi
	return current + difference * alpha
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
	npc.shown = predict(npc, os.clock())
	npc.shownYaw = npc.yaw
	rootPart.CFrame = CFrame.new(npc.shown) * CFrame.Angles(0, npc.yaw, 0)
	model:SetAttribute("McSneak", npc.crouch)
	model:SetAttribute("McSprint", npc.sprint)
	model:SetAttribute("McUserId", npc.userId) -- who it is (a game script can hit it)
	humanoid.BreakJointsOnDeath = false
	npc.humanoid = humanoid
	if npc.health then
		-- Minecraft players: their health, shown when it is not full
		humanoid.MaxHealth = npc.maxHealth
		humanoid.Health = math.max(npc.health, 0.1)
		humanoid.HealthDisplayType = Enum.HumanoidHealthDisplayType.DisplayWhenDamaged
	end
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
			track.Looped = name ~= "slash"
			if name == "slash" then
				track.Priority = Enum.AnimationPriority.Action
			end
			npc.tracks[name] = track
		end
	end
end

local function createNpc(server, player)
	return {
		userId = player.u, name = tostring(player.n), display = tostring(player.d or player.n),
		anim = nil, removed = false, model = nil, rootPart = nil, tracks = {},
		-- the newest snapshot: position + velocity at the local time sampleAt
		position = Vector3.zero, velocity = Vector3.zero, air = false, gravity = 0, sampleAt = 0, yaw = 0, speed = 0,
		crouch = false, sprint = false,
		-- what is shown: prediction + a correction that fades away
		shown = nil, correction = Vector3.zero, shownYaw = 0,
	}
end

-- Builds the avatar. Call it only after the first snapshot is set: for players without a Roblox avatar (e.g. from
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
	local sid = if type(data.sid) == "string" then data.sid else nil
	if data.bye then
		goodbyes[event.SenderIp] = sid
		removeServer(event.SenderIp)
		return
	end
	if sid ~= nil and goodbyes[event.SenderIp] == sid then
		return -- a snapshot that was on its way when this game server said goodbye
	end
	local now = os.clock()
	local server = remoteServers[event.SenderIp]
	if not server then
		local folder = Instance.new("Folder")
		folder.Name = "Server " .. tostring(data.label)
		folder.Parent = root
		server = { ip = event.SenderIp, label = tostring(data.label or "?"), folder = folder, npcs = {} }
		remoteServers[event.SenderIp] = server
		print("[PlayerSync " .. LABEL .. "] sees game server " .. server.label)
	end
	-- Snapshot time on our clock: the sender's time + the smallest difference seen so far (= the fastest way through
	-- Bridge). A snapshot that waited longer is that much older - the prediction carries it further.
	local sampleAt = now
	local t = tonumber(data.t)
	if t then
		if sid ~= server.sid then
			server.sid, server.lastT, server.offset = sid, nil, nil -- the other game server started again
		end
		if server.lastT and t <= server.lastT then
			return -- older than what is shown already: never go back
		end
		server.lastT = t
		local difference = now - t
		server.offset = if server.offset == nil
			then difference
			else math.min(difference, server.offset + (now - server.offsetAt) * DRIFT)
		server.offsetAt = now
		sampleAt = t + server.offset
	end
	server.lastSeen = now
	local gravity = tonumber(data.g) or 0
	local seen = {}
	for _, player in ipairs(data.players or {}) do
		if type(player) == "table" and type(player.u) == "number" and type(player.p) == "table" then
			seen[player.u] = true
			local npc = server.npcs[player.u]
			local isNew = npc == nil
			if isNew then
				npc = createNpc(server, player)
			end
			-- where the NPC is right now (with the old snapshot) - the new one continues from there without a jump
			local before = if npc.shown then predict(npc, now) + npc.correction else nil
			npc.position = vector(player.p, Vector3.zero) + OFFSET
			npc.velocity = vector(player.w, Vector3.zero)
			npc.air = player.a == true
			npc.gravity = gravity
			npc.sampleAt = sampleAt
			npc.yaw = tonumber(player.r) or 0
			npc.crouch = player.c == true
			npc.sprint = player.sp == true
			-- the player swings his arm (hits / builds): once per swing
			local swing = player.sw == true
			if swing and not npc.swung and npc.tracks.slash then
				npc.tracks.slash:Play(0.05)
			end
			npc.swung = swing
			npc.health = tonumber(player.h)
			npc.maxHealth = math.max(tonumber(player.mh) or 20, 1)
			if npc.humanoid and npc.health then
				npc.humanoid.MaxHealth = npc.maxHealth
				npc.humanoid.Health = math.max(npc.health, 0.1) -- never 0: the NPC must not "die"
				npc.humanoid.HealthDisplayType = Enum.HumanoidHealthDisplayType.DisplayWhenDamaged
			end
			if npc.model then
				-- the client scripts show the pose (crouching) - attributes replicate to every player
				npc.model:SetAttribute("McSneak", npc.crouch)
				npc.model:SetAttribute("McSprint", npc.sprint)
			end
			npc.speed = if type(player.w) == "table"
				then Vector3.new(npc.velocity.X, 0, npc.velocity.Z).Magnitude
				else tonumber(player.s) or 0
			if before then
				-- no jump to the new snapshot: the difference fades away within SMOOTH seconds
				local correction = before - predict(npc, now)
				npc.correction = if correction.Magnitude > TELEPORT then Vector3.zero else correction
			end
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
	local want = if npc.air then "fall"
		elseif npc.speed > 18 or (npc.sprint and npc.speed > 0.5) then "run"
		elseif npc.speed > 0.5 then "walk"
		else "idle"
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
	local fade = math.exp(-dt / SMOOTH)
	local turn = 1 - math.exp(-dt * 15)
	local now = os.clock()
	for senderIp, server in pairs(remoteServers) do
		if now - server.lastSeen > TIMEOUT then
			removeServer(senderIp)
		else
			for _, npc in pairs(server.npcs) do
				if npc.rootPart then
					npc.correction = if npc.correction.Magnitude < 0.001 then Vector3.zero else npc.correction * fade
					npc.shown = predict(npc, now) + npc.correction
					npc.shownYaw = turnTowards(npc.shownYaw, npc.yaw, turn)
					npc.rootPart.CFrame = CFrame.new(npc.shown) * CFrame.Angles(0, npc.shownYaw, 0)
					animate(npc)
				end
			end
		end
	end
end)

-- Latest: of several waiting snapshots of a game server only the newest is handled
client:Subscribe(nil, TOPIC, onSnapshot, { Latest = true })
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
				w = { round(velocity.X, 0.01), round(velocity.Y, 0.01), round(velocity.Z, 0.01) }, -- studs per second
				r = round(math.atan2(-look.X, -look.Z), 0.001), -- yaw: CFrame.Angles(0, r, 0) looks the same way
				s = round(Vector3.new(velocity.X, 0, velocity.Z).Magnitude, 0.1),
				a = humanoid.FloorMaterial == Enum.Material.Air,
				c = character:GetAttribute("McSneak") == true, -- sneaking / sprinting (set by a game script, e.g. MinecraftWorld)
				sp = character:GetAttribute("McSprint") == true,
				sw = character:GetAttribute("McSwing") == true,
			}
			table.insert(list, entry)
			-- what counts as "moved": 5 cm, a few degrees, other velocity / air state
			table.insert(parts, table.concat({ entry.u, steps(position.X, 0.05), steps(position.Y, 0.05),
				steps(position.Z, 0.05), steps(entry.r, 0.05), steps(velocity.X, 0.5), steps(velocity.Y, 0.5),
				steps(velocity.Z, 0.5), tostring(entry.a), tostring(entry.c), tostring(entry.sp), tostring(entry.sw) }, ":"))
		end
	end
	return list, table.concat(parts, "|")
end

local function gravity()
	local ok, value = pcall(function()
		return workspace.Gravity
	end)
	return if ok and type(value) == "number" then value else 196.2
end

client:BindToClose(function()
	-- the others remove our NPCs at once instead of after the timeout
	client:Publish(nil, TOPIC, { v = 2, label = LABEL, sid = SESSION, bye = true })
end)

-- Measure the own players SAMPLE_RATE times per second. PublishLatest keeps only the newest snapshot, it goes out
-- with the next poll - so whatever goes out is never older than 1 / SAMPLE_RATE seconds.
local lastKey, lastSent, sinceSample = nil, 0, 0
RunService.Heartbeat:Connect(function(dt)
	sinceSample += dt
	if sinceSample < 1 / SAMPLE_RATE or client.State == "destroyed" then
		return
	end
	sinceSample = 0
	local players, key = snapshot()
	local now = os.clock()
	if key ~= lastKey or now - lastSent >= KEEPALIVE then
		local ok, err = pcall(client.PublishLatest, client, nil, TOPIC,
			{ v = 2, label = LABEL, sid = SESSION, t = round(now, 0.001), g = gravity(), players = players })
		if ok then
			lastKey, lastSent = key, now
		elseif client.State ~= "destroyed" then
			warn("[PlayerSync " .. LABEL .. "] " .. tostring(err))
		end
	end
end)
-- endregion

print("[PlayerSync " .. LABEL .. "] started - Bridge server " .. client.Server)
