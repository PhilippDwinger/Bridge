--[[
	MinecraftPlayer - moving, looking and talking like in Minecraft (LocalScript in StarterPlayerScripts)

	- Camera like Minecraft: the mouse is caught (no cursor), it turns the view; F5 (or V) switches first person ->
	  third person from behind -> from the front (4 blocks away, pulled closer by walls). Crosshair in first person.
	- Walking like Minecraft (Roblox's own controls are off): W A S D relative to where you look - also in the front
	  view -, Space (hold = jump again), Shift = sneak (slower, eyes lower, you do not fall off edges), Ctrl = sprint
	  only while it is held and you walk forward. Speeds, jump height, gravity: MinecraftCharacter.
	- Animations: Minecraft's own (MinecraftCharacter.animate) on the own character - Roblox replicates them to the
	  others; the head follows the look up / down on everybody (attribute McPitch).
	- Chat: T opens it. Messages go to Minecraft, Minecraft's chat comes in; "/..." runs a Minecraft command (the
	  answer only you see), "/skin <Minecraft name>" wears that account's skin, "/skin" the default one again.
	For MinecraftClient: player attributes McEye / McLook (where the eyes are / look, for building), McGuiOpen
	(inventory open: mouse free, no walking), McSwingAt (swing the arm).
]]
local GuiService = game:GetService("GuiService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local TextChatService = game:GetService("TextChatService")
local UserInputService = game:GetService("UserInputService")

-- (missing = Rojo still serves an older project: restart "rojo serve" and connect the plugin again)
local characterModule = ReplicatedStorage:WaitForChild("MinecraftCharacter", 15)
if not characterModule then
	error("[MinecraftWorld] ReplicatedStorage.MinecraftCharacter fehlt - Rojo neu starten: "
		.. "rojo serve minecraft-world.project.json --port 34874, dann im Rojo-Plugin neu verbinden")
end
local Character = require(characterModule :: any)
local remotes = ReplicatedStorage:WaitForChild("MinecraftWorld")
local moveRemote = remotes:WaitForChild("Move") :: RemoteEvent
local chatRemote = remotes:WaitForChild("Chat") :: RemoteEvent

local player = Players.LocalPlayer
local THIRD_DISTANCE = 4 * Character.STUDS_PER_BLOCK -- Minecraft: the camera is 4 blocks away
local FOV = 70 -- Minecraft's default ("Normal")
local SPRINT_FOV = 1.15 -- Minecraft widens the view with the speed
local SENSITIVITY = math.rad(0.15) -- Minecraft's default mouse speed: 0.15 degrees per pixel
local MAX_PITCH = math.rad(89.9)
local SEND_EVERY = 0.1 -- seconds between two head-pitch updates to the server

local yaw, pitch = 0, 0
local view = 1 -- 1 first person, 2 from behind, 3 from the front
local sneaking, sprinting = false, false
local eyeHeight = Character.EYE_HEIGHT
local fov = FOV
local animation = nil
local animatedCharacter = nil
local sent = { sneak = nil :: boolean?, sprint = nil :: boolean?, pitch = 0, at = 0 }

-- Roblox's own walking is off: Minecraft walks relative to where the player looks (the camera may face him)
local controls = nil
local function disableControls()
	if controls then
		pcall(function()
			controls:Disable()
		end)
	end
end
task.spawn(function()
	local ok, result = pcall(function()
		local module = require(player:WaitForChild("PlayerScripts"):WaitForChild("PlayerModule") :: any)
		return module:GetControls()
	end)
	if ok and result then
		controls = result
		disableControls()
	end
end)

local function mouseSpeed(): number
	local ok, value = pcall(function()
		return UserSettings():GetService("UserGameSettings").MouseSensitivity
	end)
	return if ok and type(value) == "number" and value > 0 then value else 1
end

local function chatFocused(): boolean
	local ok, focused = pcall(function()
		return TextChatService.ChatInputBarConfiguration.IsFocused
	end)
	return (ok and focused == true) or UserInputService:GetFocusedTextBox() ~= nil
end

local function guiOpen(): boolean
	return player:GetAttribute("McGuiOpen") == true or player:GetAttribute("McMenuOpen") == true or GuiService.MenuIsOpen
		or chatFocused()
end

local function keyDown(...): boolean
	for _, key in ipairs({ ... }) do
		if UserInputService:IsKeyDown(key) then
			return true
		end
	end
	return false
end

-- region crosshair (first person only, like Minecraft)
local hud = Instance.new("ScreenGui")
hud.Name = "MinecraftCrosshair"
hud.ResetOnSpawn = false
hud.IgnoreGuiInset = true
hud.DisplayOrder = 4
hud.Parent = player:WaitForChild("PlayerGui")
local crosshair = Instance.new("Frame")
crosshair.Name = "Crosshair"
crosshair.AnchorPoint = Vector2.new(0.5, 0.5)
crosshair.Position = UDim2.fromScale(0.5, 0.5)
crosshair.Size = UDim2.fromOffset(18, 18)
crosshair.BackgroundTransparency = 1
crosshair.Parent = hud
for _, size in ipairs({ UDim2.fromOffset(18, 2), UDim2.fromOffset(2, 18) }) do
	local bar = Instance.new("Frame")
	bar.AnchorPoint = Vector2.new(0.5, 0.5)
	bar.Position = UDim2.fromScale(0.5, 0.5)
	bar.Size = size
	bar.BorderSizePixel = 0
	bar.BackgroundColor3 = Color3.new(1, 1, 1)
	bar.BackgroundTransparency = 0.2
	bar.Parent = crosshair
end
-- endregion

-- region input
local switchedAt = -math.huge
local function switchView()
	if os.clock() - switchedAt > 0.15 then
		switchedAt = os.clock()
		view = view % 3 + 1
	end
end

-- F5 like Minecraft - also when Roblox marks it as "already handled" (F5 is a Studio / Roblox key). V does the same.
UserInputService.InputBegan:Connect(function(input, processed)
	if input.KeyCode == Enum.KeyCode.F5 and not chatFocused() then
		switchView()
	elseif input.KeyCode == Enum.KeyCode.V and not processed then
		switchView()
	end
end)
-- ... and if no InputBegan comes for F5 at all: the key itself is asked every frame (see below)
local f5Down = false
local function pollF5()
	local down = UserInputService:IsKeyDown(Enum.KeyCode.F5)
	if down and not f5Down and not chatFocused() then
		switchView()
	end
	f5Down = down
end

player:GetAttributeChangedSignal("McSwingAt"):Connect(function()
	if animation then
		animation:swing()
	end
end)
-- endregion

-- region walking
local groundParams = RaycastParams.new()
groundParams.FilterType = Enum.RaycastFilterType.Exclude

local function hasGround(feet: Vector3): boolean
	-- Minecraft: sneaking stops where the hitbox, 0.6 blocks lower, would hang in the air
	local half = Character.HITBOX.X / 2 - 0.05
	local depth = 0.6 * Character.STUDS_PER_BLOCK + 0.1
	for _, corner in ipairs({ Vector3.new(half, 0, half), Vector3.new(-half, 0, half), Vector3.new(half, 0, -half),
		Vector3.new(-half, 0, -half) }) do
		if workspace:Raycast(feet + corner + Vector3.new(0, 0.1, 0), Vector3.new(0, -depth, 0), groundParams) then
			return true
		end
	end
	return false
end

-- Minecraft only jumps standing on something. Roblox's humanoid feels the floor a bit before it touches it (and
-- would jump out of the air): here the feet must really be on a block.
local function onGround(root: BasePart): boolean
	if root.AssemblyLinearVelocity.Y < -1 then
		return false
	end
	groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local half = Character.HITBOX.X / 2 - 0.05
	for _, corner in ipairs({ Vector3.new(half, 0, half), Vector3.new(-half, 0, half), Vector3.new(half, 0, -half),
		Vector3.new(-half, 0, -half) }) do
		if workspace:Raycast(feet + corner + Vector3.new(0, 0.2, 0), Vector3.new(0, -0.35, 0), groundParams) then
			return true
		end
	end
	return false
end

-- Like Minecraft's backOffFromEdge: per direction, whatever would leave the ground is not done
local function stayOnEdge(root: BasePart, move: Vector3, speed: number): Vector3
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local step = speed * 0.05 + 0.1 -- one Minecraft tick ahead
	local x, z = move.X, move.Z
	if x ~= 0 and not hasGround(feet + Vector3.new(math.sign(x) * step, 0, 0)) then
		x = 0
	end
	if z ~= 0 and not hasGround(feet + Vector3.new(0, 0, math.sign(z) * step)) then
		z = 0
	end
	if x ~= 0 and z ~= 0 and not hasGround(feet + Vector3.new(math.sign(x) * step, 0, math.sign(z) * step)) then
		z = 0
	end
	return Vector3.new(x, 0, z)
end

local lastJump = -math.huge
local function walk(humanoid: Humanoid, root: BasePart, free: boolean, dt: number)
	local forward = Vector3.new(-math.sin(yaw), 0, -math.cos(yaw))
	local right = Vector3.new(math.cos(yaw), 0, -math.sin(yaw))
	local ahead, side = 0, 0
	if not free then
		ahead = (if keyDown(Enum.KeyCode.W) then 1 else 0) - (if keyDown(Enum.KeyCode.S) then 1 else 0)
		side = (if keyDown(Enum.KeyCode.D) then 1 else 0) - (if keyDown(Enum.KeyCode.A) then 1 else 0)
	end
	local move = forward * ahead + right * side
	if move.Magnitude > 1 then
		move = move.Unit
	end
	sneaking = not free and keyDown(Enum.KeyCode.LeftShift, Enum.KeyCode.RightShift)
	-- sprinting: only while Ctrl is held and you walk forward (and not while sneaking)
	sprinting = not free and keyDown(Enum.KeyCode.LeftControl) and ahead > 0 and not sneaking
	local speed = if sneaking then Character.SNEAK_SPEED elseif sprinting then Character.SPRINT_SPEED else Character.WALK_SPEED
	humanoid.WalkSpeed = speed
	if sneaking and humanoid.FloorMaterial ~= Enum.Material.Air and move.Magnitude > 0 then
		groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
		move = stayOnEdge(root, move, speed)
	end
	humanoid:Move(move, false)
	if move.Magnitude == 0 and onGround(root) then
		-- no key pressed, feet on a block: Minecraft's ground friction (x 0.546 per tick) - nobody slides
		local velocity = root.AssemblyLinearVelocity
		local keep = if Vector3.new(velocity.X, 0, velocity.Z).Magnitude < 0.3 then 0 else 0.546 ^ (20 * dt)
		root.AssemblyLinearVelocity = Vector3.new(velocity.X * keep, velocity.Y, velocity.Z * keep)
	end
	-- Jumping like Minecraft: only with the feet on a block, held = again after landing, at most every 10 ticks
	local space = not free and keyDown(Enum.KeyCode.Space)
	if not space then
		lastJump = -math.huge
	end
	if space and humanoid.Health > 0 and os.clock() - lastJump >= 0.5 and onGround(root) then
		lastJump = os.clock()
		if humanoid:GetState() == Enum.HumanoidStateType.Freefall then
			-- on the very edge of a block Roblox's humanoid thinks it falls (it only looks under its middle): jump anyway
			local velocity = root.AssemblyLinearVelocity
			root.AssemblyLinearVelocity = Vector3.new(velocity.X, Character.JUMP_VELOCITY, velocity.Z)
		else
			humanoid.Jump = true
		end
	else
		humanoid.Jump = false
	end
	humanoid.AutoRotate = false
	if humanoid.Health > 0 then
		root.CFrame = CFrame.new(root.Position) * CFrame.Angles(0, yaw, 0) -- the body turns with the view
	end
end
-- endregion

-- region camera
local cameraParams = RaycastParams.new()
cameraParams.FilterType = Enum.RaycastFilterType.Exclude

local function clip(from: Vector3, direction: Vector3, character: Model): number
	local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
	cameraParams.FilterDescendantsInstances = if npcs then { character, npcs } else { character }
	local hit = workspace:Raycast(from, direction * THIRD_DISTANCE, cameraParams)
	return if hit then math.max(0, (hit.Position - from).Magnitude - 0.3) else THIRD_DISTANCE
end

local function hideCharacter(character: Model, hidden: boolean)
	for _, item in ipairs(character:GetDescendants()) do
		if item:IsA("BasePart") or item:IsA("Decal") then -- (the skin Textures too, they are Decals)
			item.LocalTransparencyModifier = if hidden then 1 else 0
		end
	end
end
-- endregion

-- region the head follows the look (everybody: own character, other players, Minecraft players)
local shownPitch = setmetatable({}, { __mode = "k" })
local function lookAll(dt: number)
	local blend = 1 - math.exp(-dt * 20)
	local function apply(model: Model, wanted: number)
		local current = shownPitch[model] or 0
		current += (wanted - current) * blend
		shownPitch[model] = current
		Character.look(model, current)
	end
	for _, other in ipairs(Players:GetPlayers()) do
		local character = other.Character
		if character then
			apply(character, if other == player then pitch else tonumber(character:GetAttribute("McPitch")) or 0)
		end
	end
	local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
	if npcs then
		for _, folder in ipairs(npcs:GetChildren()) do
			for _, model in ipairs(folder:GetChildren()) do
				if model:IsA("Model") then
					apply(model, tonumber(model:GetAttribute("McPitch")) or 0)
				end
			end
		end
	end
end
-- endregion

local function onCharacter(character: Model)
	local root = character:WaitForChild("HumanoidRootPart", 10) :: BasePart?
	local humanoid = character:WaitForChild("Humanoid", 10) :: Humanoid?
	if not root or not humanoid or player.Character ~= character then
		return
	end
	local _, rootYaw, _ = root.CFrame:ToOrientation()
	yaw, pitch = rootYaw, 0
	disableControls() -- (a new character may switch them on again)
	if animation then
		animation:destroy()
	end
	animation = Character.animate(character)
	animatedCharacter = character
	humanoid.Died:Connect(function()
		if animatedCharacter == character and animation then
			animation:die()
		end
		root.Anchored = true -- lies where it fell (the death animation tips it over, not the physics)
	end)
end
player.CharacterAdded:Connect(onCharacter)
if player.Character then
	task.spawn(onCharacter, player.Character)
end

RunService:BindToRenderStep("MinecraftPlayer", Enum.RenderPriority.Camera.Value, function(dt)
	pollF5()
	local free = guiOpen()
	if free then
		if player:GetAttribute("McGuiOpen") ~= true and player:GetAttribute("McMenuOpen") ~= true then -- (they do it)
			UserInputService.MouseBehavior = Enum.MouseBehavior.Default
			UserInputService.MouseIconEnabled = true
		end
	else
		UserInputService.MouseBehavior = Enum.MouseBehavior.LockCenter
		UserInputService.MouseIconEnabled = false
		local delta = UserInputService:GetMouseDelta()
		local speed = SENSITIVITY * mouseSpeed()
		yaw -= delta.X * speed
		pitch = math.clamp(pitch + delta.Y * speed, -MAX_PITCH, MAX_PITCH)
	end
	local camera = workspace.CurrentCamera
	local character = player.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local root = character and character:FindFirstChild("HumanoidRootPart") :: BasePart?
	if not camera or not character or not humanoid or not root then
		return
	end
	camera.CameraType = Enum.CameraType.Scriptable
	walk(humanoid, root, free, dt)
	if animation and animatedCharacter == character then
		local velocity = root.AssemblyLinearVelocity
		animation:update(dt, { speed = Vector3.new(velocity.X, 0, velocity.Z).Magnitude, sneak = sneaking })
	end
	lookAll(dt)

	-- the eyes (lower while sneaking, smoothly - like Minecraft)
	eyeHeight += ((if sneaking then Character.SNEAK_EYE_HEIGHT else Character.EYE_HEIGHT) - eyeHeight) * (1 - math.exp(-dt * 12))
	local eye = root.Position + Vector3.new(0, eyeHeight - Character.ROOT_HEIGHT, 0)
	local rotation = CFrame.Angles(0, yaw, 0) * CFrame.Angles(-pitch, 0, 0)
	local look = rotation.LookVector
	if view == 1 then
		camera.CFrame = CFrame.new(eye) * rotation
	elseif view == 2 then
		camera.CFrame = CFrame.new(eye - look * clip(eye, -look, character)) * rotation
	else
		-- front: turned round, looking back at the player (Minecraft: yaw + 180, pitch mirrored)
		local turned = CFrame.Angles(0, yaw + math.pi, 0) * CFrame.Angles(pitch, 0, 0)
		local back = -turned.LookVector
		camera.CFrame = CFrame.new(eye + back * clip(eye, back, character)) * turned
	end
	hideCharacter(character, view == 1)
	crosshair.Visible = view == 1 and not free
	local baseFov = tonumber(player:GetAttribute("McFov")) or FOV -- (the settings menu, M)
	fov += ((if sprinting then baseFov * SPRINT_FOV else baseFov) - fov) * (1 - math.exp(-dt * 10))
	camera.FieldOfView = fov
	player:SetAttribute("McEye", eye)
	player:SetAttribute("McLook", look)

	-- the others see it: sneaking / sprinting at once, the head pitch a few times per second
	local now = os.clock()
	if sneaking ~= sent.sneak or sprinting ~= sent.sprint
		or (math.abs(pitch - sent.pitch) > 0.03 and now - sent.at > SEND_EVERY) then
		sent.sneak, sent.sprint, sent.pitch, sent.at = sneaking, sprinting, pitch, now
		moveRemote:FireServer(sneaking, sprinting, math.floor(pitch * 100 + 0.5) / 100)
	end
end)

-- region chat
pcall(function()
	TextChatService.ChatInputBarConfiguration.KeyboardKeyCode = Enum.KeyCode.T -- Minecraft opens the chat with T
end)

local function generalChannel(): TextChannel?
	local channels = TextChatService:FindFirstChild("TextChannels")
	local channel = channels and channels:FindFirstChild("RBXGeneral")
	return if channel and channel:IsA("TextChannel") then channel else nil
end

local function escape(text: string): string
	return (string.gsub(text, "[&<>\"']", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;",
		["'"] = "&apos;" }))
end

local function show(text: string, color: string)
	local channel = generalChannel()
	if channel then
		pcall(function()
			channel:DisplaySystemMessage(string.format('<font color="%s">%s</font>', color, escape(text)))
		end)
	end
end

-- What I write goes to Minecraft too; "/..." only to Minecraft (not into the Roblox chat)
TextChatService.OnIncomingMessage = function(message: TextChatMessage)
	local source = message.TextSource
	if message.Status == Enum.TextChatMessageStatus.Sending and source and source.UserId == player.UserId then
		local text = message.Text
		chatRemote:FireServer(text)
		if string.sub(text, 1, 1) == "/" then
			pcall(function()
				message.Text = "" -- an empty message is not sent
			end)
			local hidden = Instance.new("TextChatMessageProperties")
			hidden.Text = ""
			return hidden
		end
	end
	return nil
end

chatRemote.OnClientEvent:Connect(function(kind, a, b, c)
	if kind == "mc" then
		-- Minecraft: a = "chat" | "command" | "system", b = text, c = who wrote it
		local text = if type(b) == "string" then b else ""
		if a == "chat" and type(c) == "string" then
			show("<" .. c .. "> " .. text, "#FFFFFF")
		elseif a == "system" then
			show(text, "#FFFF55")
		else
			show(text, "#FFFFFF")
		end
	elseif kind == "reply" and type(a) == "table" then
		for _, line in ipairs(a) do
			if type(line) == "string" then
				show(line, "#AAAAAA")
			end
		end
	end
end)
-- endregion
