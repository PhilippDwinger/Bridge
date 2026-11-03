--[[
	MinecraftPlayer - moving, looking and talking like in Minecraft (LocalScript in StarterPlayerScripts)

	- Camera like Minecraft: the mouse is caught (no cursor), it turns the view; F5 (or V) switches first person ->
	  third person from behind -> from the front (4 blocks away, pulled closer by walls). Crosshair in first person.
	- Walking like Minecraft (Roblox's own controls are off): W A S D relative to where you look - also in the front
	  view -, Space (hold = jump again), Shift = sneak (slower, eyes lower, you do not fall off edges), Ctrl = sprint
	  only while it is held and you walk forward, or W twice quickly (like Minecraft: sprinting until you let go of W
	  - in Studio this is the way: Studio takes Ctrl + W for itself when Ctrl is pressed first; jumping while
	  sprinting pushes forward). Minecraft's own movement:
	  the speed is set every frame with Minecraft's friction (ground: quick, air: momentum), steps up to 0.6 blocks
	  are walked up. Speeds, jump height, gravity: MinecraftCharacter.
	- Game modes (player attribute McGameMode from the server): creative = Space twice to fly (Space up, Shift down,
	  Ctrl twice as fast, landing stops it), spectator = always flying, through blocks, only other spectators see
	  him (as a see-through head) - Minecraft players in spectator only spectators see too.
	- Water / lava like Minecraft (travelInWater / travelInLava): slow, Space swims up, you sink slowly, at an edge you
	  jump out; sprinting with the eyes under water = swimming (lying in the water with the swim animation, the eyes
	  low, up / down where you look). Player attributes McFluid / McEyeInWater for MinecraftClient (air, no fall).
	- Animations: Minecraft's own (MinecraftCharacter.animate) on the own character - Roblox replicates them to the
	  others; the head follows the look up / down on everybody (attribute McPitch).
	- Chat: T opens it. Messages go to Minecraft, Minecraft's chat comes in; "/..." runs a Minecraft command (the
	  answer only you see), "/skin <Minecraft name>" wears that account's skin, "/skin" the default one again.
	For MinecraftClient: player attributes McEye / McLook (where the eyes are / look, for building), McGround (feet
	on a block), McFlying, McGuiOpen (inventory open: mouse free, no walking), McSwingAt (swing the arm).
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
local inventoryRemote = remotes:WaitForChild("Inventory", 10) :: RemoteEvent?
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
local sent = { sneak = nil :: boolean?, sprint = nil :: boolean?, pitch = 0, at = 0, flying = nil :: boolean?, blocking = false,
	swimming = nil :: boolean? }

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
		player:SetAttribute("McView", view) -- (MinecraftClient: the crosshair only in first person)
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

-- region status effects (from Minecraft: the player attribute McEffects, JSON [{id, amp, dur, ...}])
local HttpService = game:GetService("HttpService")
local effects: { [string]: any } = {} -- id -> {amp, dur, ...}
local skyModule: any = nil
local function readEffects()
	local list = {}
	local ok, decoded = pcall(function()
		return HttpService:JSONDecode(player:GetAttribute("McEffects") or "[]")
	end)
	if ok and type(decoded) == "table" then
		for _, effect in ipairs(decoded) do
			if type(effect) == "table" and type(effect.id) == "string" then
				list[effect.id] = effect
			end
		end
	end
	effects = list
	if not skyModule then
		local found = ReplicatedStorage:FindFirstChild("MinecraftSky")
		if found then
			local loaded, module = pcall(require, found :: any)
			skyModule = if loaded then module else false
		end
	end
	if skyModule then
		skyModule.effects = list -- (night vision, blindness: MinecraftSky)
	end
end
player:GetAttributeChangedSignal("McEffects"):Connect(readEffects)
readEffects()

-- Minecraft: speed +20 % per level, slowness -15 % per level (the walking speed attribute)
local function effectSpeed(): number
	local factor = 1
	if effects.speed then
		factor *= 1 + 0.2 * ((tonumber(effects.speed.amp) or 0) + 1)
	end
	if effects.slowness then
		factor *= math.max(0, 1 - 0.15 * ((tonumber(effects.slowness.amp) or 0) + 1))
	end
	return factor
end
-- endregion

-- region walking + flying (Minecraft's own movement, per tick turned into per frame)
local TICKS = 20
local GROUND_KEEP = 0.546 -- per tick on the ground: block friction 0.6 x 0.91 (no key: standing still in ~0.2 s)
local AIR_KEEP = 0.91 -- per tick in the air / flying: what is left of the speed
local FLY_VERTICAL_KEEP = 0.6
local BLOCK = Character.STUDS_PER_BLOCK
local FLY_SPEED = 0.05 * 0.98 / (1 - AIR_KEEP) * TICKS * BLOCK -- creative flying: 10.9 blocks/s (sprinting x 2)
local FLY_VERTICAL = 7.5 * BLOCK -- Space / Shift while flying: 7.5 blocks/s
local SPRINT_JUMP = 0.2 * TICKS * BLOCK -- jumping while sprinting: + 0.2 blocks/tick forward
local STEP_HEIGHT = 0.6 * BLOCK -- Minecraft walks up 0.6 blocks without jumping (slabs, trapdoors)
local DOUBLE_TAP = 0.35 -- 7 ticks: Space twice = fly (creative)
-- In water / lava, Minecraft's LivingEntity.travelInWater / travelInLava, per tick (blocks / tick):
-- speed = (speed + keys x 0.02 x 0.98) x keep, up: (up + 0.04 with Space) x keep - gravity / 16 (lava: / 4)
local FLUID = {
	water = { keep = 0.8, sprintKeep = 0.9, vertical = 0.8, sink = 0.08 / 16 },
	lava = { keep = 0.5, sprintKeep = 0.5, vertical = 0.5, sink = 0.08 / 4 },
}
local FLUID_ACCEL = 0.02 * 0.98
local FLUID_UP = 0.04 -- Space held (jumpInLiquid)
local OUT_OF_FLUID = 0.3 -- blocks / tick up: at an edge Minecraft jumps out (jumpOutOfFluid)

local groundParams = RaycastParams.new()
groundParams.FilterType = Enum.RaycastFilterType.Exclude
pcall(function()
	groundParams.RespectCanCollide = true -- redstone, levers, buttons have no collision: nobody stands on them
end)

local flying = false
local flyingSince = 0
local lastSpaceTap = -math.huge
local lastJump = -math.huge

local function gameMode(): string
	local mode = player:GetAttribute("McGameMode")
	return if type(mode) == "string" then mode else "survival"
end

local function hasGround(feet: Vector3): boolean
	-- Minecraft: sneaking stops where the hitbox, 0.6 blocks lower, would hang in the air
	local half = Character.HITBOX.X / 2 - 0.05
	local depth = 0.6 * BLOCK + 0.1
	for _, corner in ipairs({ Vector3.new(half, 0, half), Vector3.new(-half, 0, half), Vector3.new(half, 0, -half),
		Vector3.new(-half, 0, -half) }) do
		if workspace:Raycast(feet + corner + Vector3.new(0, 0.1, 0), Vector3.new(0, -depth, 0), groundParams) then
			return true
		end
	end
	return false
end

-- Minecraft only jumps standing on something - here the feet must really be on a block (any corner of the hitbox:
-- standing on the very edge counts, like in Minecraft)
local function onGround(root: BasePart): boolean
	if root.AssemblyLinearVelocity.Y < -1 then
		return false
	end
	groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local half = Character.HITBOX.X / 2 - 0.05
	for _, corner in ipairs({ Vector3.new(half, 0, half), Vector3.new(-half, 0, half), Vector3.new(half, 0, -half),
		Vector3.new(-half, 0, -half), Vector3.zero }) do
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

--[[
	Minecraft's horizontal movement: every tick the speed keeps a part of itself (friction) and moves towards what the
	keys want - on the ground fast, in the air slowly (momentum). Set directly on the root part every frame (no
	friction there): nothing can make the player stick, nobody glides on.
]]
local function steer(root: BasePart, target: Vector3, keep: number): Vector3
	local velocity = root.AssemblyLinearVelocity
	local flat = Vector3.new(velocity.X, 0, velocity.Z)
	local new = target + (flat - target) * keep
	if target.Magnitude < 0.01 and new.Magnitude < 0.3 then
		new = Vector3.zero
	end
	root.AssemblyLinearVelocity = Vector3.new(new.X, velocity.Y, new.Z)
	return new
end

-- Minecraft walks up steps up to 0.6 blocks high (a slab, a closed trapdoor) without jumping
-- Ladders, vines, scaffolding (Minecraft's BlockTags.CLIMBABLE): the body in one of their blocks (their parts in the
-- world are named after the block)
local CLIMBABLE = { ["minecraft:ladder"] = true, ["minecraft:vine"] = true, ["minecraft:scaffolding"] = true,
	["minecraft:twisting_vines"] = true, ["minecraft:twisting_vines_plant"] = true, ["minecraft:weeping_vines"] = true,
	["minecraft:weeping_vines_plant"] = true, ["minecraft:cave_vines"] = true, ["minecraft:cave_vines_plant"] = true }
local climbParams = OverlapParams.new()
climbParams.FilterType = Enum.RaycastFilterType.Include
local climbCheckAt, climbCached = 0, false
local function onClimbable(root: BasePart): boolean
	local now = os.clock()
	if now - climbCheckAt < 0.05 then
		return climbCached
	end
	climbCheckAt = now
	climbCached = false
	local worldFolder = workspace:FindFirstChild("MinecraftWorld")
	if not worldFolder then
		return false
	end
	climbParams.FilterDescendantsInstances = { worldFolder }
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local center = CFrame.new(feet + Vector3.new(0, 0.9 * BLOCK, 0))
	for _, part in ipairs(workspace:GetPartBoundsInBox(center, Vector3.new(0.7, 1.7, 0.7) * BLOCK, climbParams)) do
		local model = part.Parent
		local name = model and model:IsA("Model") and (string.match(model.Name, "^([^%[#]+)") or model.Name)
		if name and CLIMBABLE[name] then
			climbCached = true
			break
		end
	end
	return climbCached
end

local function stepUp(root: BasePart, horizontal: Vector3, dt: number)
	if horizontal.Magnitude < 0.5 then
		return
	end
	local direction = horizontal.Unit
	local width = Character.HITBOX.X - 0.1
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local ahead = horizontal.Magnitude * dt + 0.1
	groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
	local ok, low, wall, top = pcall(function()
		local lowBox = Vector3.new(width, STEP_HEIGHT - 0.04, width)
		local highBox = Vector3.new(width, Character.HITBOX.Y - STEP_HEIGHT - 0.04, width)
		local lowHit = workspace:Blockcast(CFrame.new(feet + Vector3.new(0, 0.02 + lowBox.Y / 2, 0)), lowBox,
			direction * ahead, groundParams)
		local wallHit = workspace:Blockcast(CFrame.new(feet + Vector3.new(0, STEP_HEIGHT + 0.02 + highBox.Y / 2, 0)), highBox,
			direction * ahead, groundParams)
		local downFrom = feet + direction * ahead + Vector3.new(0, STEP_HEIGHT + 0.05, 0)
		local topHit = workspace:Blockcast(CFrame.new(downFrom), Vector3.new(width, 0.02, width),
			Vector3.new(0, -(STEP_HEIGHT + 0.05), 0), groundParams)
		return lowHit, wallHit, topHit
	end)
	if not ok or not low or wall or not top then
		return
	end
	local rise = top.Position.Y - feet.Y
	if rise > 0.15 and rise <= STEP_HEIGHT + 0.01 then -- (Minecraft's smallest step: 1/16 block)
		root.CFrame += Vector3.new(0, rise + 0.02, 0)
	end
end

-- W twice quickly: sprinting until W is let go (Minecraft: twice within 7 ticks)
local lastForwardTap = -math.huge
local tapSprint = false
UserInputService.InputBegan:Connect(function(input, processed)
	if input.KeyCode ~= Enum.KeyCode.W or processed or chatFocused() then
		return
	end
	local now = os.clock()
	if now - lastForwardTap < DOUBLE_TAP then
		tapSprint = true
		lastForwardTap = -math.huge
	else
		lastForwardTap = now
	end
end)

-- Space twice quickly: fly (creative) - like Minecraft
UserInputService.InputBegan:Connect(function(input, processed)
	if input.KeyCode ~= Enum.KeyCode.Space or processed or chatFocused() then
		return
	end
	if gameMode() ~= "creative" then
		lastSpaceTap = -math.huge
		return
	end
	local now = os.clock()
	if now - lastSpaceTap < DOUBLE_TAP then
		flying = not flying
		flyingSince = now
		lastSpaceTap = -math.huge
	else
		lastSpaceTap = now
	end
end)

local antiGravity: VectorForce? = nil
local yawAlign: AlignOrientation? = nil

local fluidHere: string? = nil -- the fluid the body is in (any part of the hitbox)
local eyeFluid: string? = nil -- the fluid the eyes are in
local swimming = false -- Minecraft's swimming: sprinting under water (lying in the water)

-- Where the body / the eyes are (Minecraft: isInWater = the hitbox touches water, isUnderWater = the eyes)
local function senseFluids(root: BasePart, eyeHeight: number)
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	local body = nil
	for _, height in ipairs({ 0.1, 0.9 * BLOCK, 1.7 * BLOCK }) do
		body = body or Character.fluidAt(feet + Vector3.new(0, height, 0))
	end
	fluidHere = body
	eyeFluid = Character.fluidAt(feet + Vector3.new(0, eyeHeight, 0))
	if player:GetAttribute("McFluid") ~= body then
		player:SetAttribute("McFluid", body) -- (MinecraftClient: no fall damage in water)
	end
	local underwater = eyeFluid == "water"
	if player:GetAttribute("McEyeInWater") ~= underwater then
		player:SetAttribute("McEyeInWater", underwater) -- (MinecraftClient: air bubbles, drowning)
	end
end

-- Minecraft's jumpOutOfFluid: pushing against an edge, if the hitbox fits 0.6 blocks higher there - out you go
local function canJumpOut(root: BasePart, move: Vector3): boolean
	if move.Magnitude < 0.1 then
		return false
	end
	local direction = Vector3.new(move.X, 0, move.Z).Unit
	local width = Character.HITBOX.X - 0.1
	local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
	groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
	local ok, blocked, free = pcall(function()
		local box = Vector3.new(width, Character.HITBOX.Y - 0.1, width)
		local here = workspace:Blockcast(CFrame.new(feet + Vector3.new(0, 0.05 + box.Y / 2, 0)), box, direction * 0.3,
			groundParams)
		local higher = workspace:Blockcast(CFrame.new(feet + Vector3.new(0, 0.6 * BLOCK + 0.05 + box.Y / 2, 0)), box,
			direction * 0.3, groundParams)
		return here, higher
	end)
	return ok and blocked ~= nil and free == nil
end

--[[
	Riding (the server sets McRideMode / McRideSpeed / McRideJump from Minecraft: what he rides and how fast it goes):
	"drive" - a horse / pig / strider / camel: he walks with ITS speed (blocks/s, 0 = it cannot be steered: no saddle,
	a pig without a carrot on a stick) and jumps its height; "boat" - floats on the water (feet at the surface), slow on
	land; "cart" - a minecart: Minecraft moves it, he sits in it (MinecraftClient says where: McCartAt).
	Shift gets him off (Minecraft: sneaking).
]]
local dismountAsked = 0
local function ride(humanoid: Humanoid, root: BasePart, move: Vector3, shift: boolean, space: boolean, mode: string, dt: number)
	sneaking, sprinting, swimming, flying = false, false, false, false
	tapSprint = false
	if shift and inventoryRemote and os.clock() - dismountAsked > 0.5 then
		dismountAsked = os.clock()
		inventoryRemote:FireServer("dismount")
	end
	humanoid.AutoRotate = false
	local speed = (tonumber(player:GetAttribute("McRideSpeed")) or 0) * BLOCK
	if mode == "cart" then
		humanoid.PlatformStand = true
		if antiGravity then
			antiGravity.Force = Vector3.new(0, root.AssemblyMass * workspace.Gravity, 0)
			antiGravity.Enabled = true
		end
		local cart = player:GetAttribute("McCartAt")
		if typeof(cart) == "CFrame" then
			root.CFrame = CFrame.new(cart.Position + Vector3.new(0, Character.ROOT_HEIGHT, 0)) * CFrame.Angles(0, yaw, 0)
		end
		root.AssemblyLinearVelocity = Vector3.zero
		humanoid:Move(Vector3.zero, false)
		humanoid.Jump = false
		return
	end
	local grounded = onGround(root)
	if mode == "boat" then
		local feet = root.Position - Vector3.new(0, Character.ROOT_HEIGHT, 0)
		local under = Character.fluidAt(feet + Vector3.new(0, 0.3 * BLOCK, 0)) == "water"
		local afloat = under or Character.fluidAt(feet - Vector3.new(0, 0.15 * BLOCK, 0)) == "water"
		-- (Minecraft's boat: ~8 blocks/s on water, hardly moves on land)
		local horizontal = steer(root, move * (if afloat then speed else 0.6 * BLOCK),
			(if afloat then 0.9 elseif grounded then GROUND_KEEP else AIR_KEEP) ^ (TICKS * dt))
		humanoid.PlatformStand = afloat
		if antiGravity then
			antiGravity.Force = Vector3.new(0, root.AssemblyMass * workspace.Gravity, 0)
			antiGravity.Enabled = afloat
		end
		local vy = if under then 0.08 * TICKS * BLOCK elseif afloat then 0 else root.AssemblyLinearVelocity.Y
		root.AssemblyLinearVelocity = Vector3.new(horizontal.X, vy, horizontal.Z)
		humanoid.WalkSpeed = horizontal.Magnitude
		humanoid:Move(if not afloat and horizontal.Magnitude > 0.01 then horizontal.Unit else Vector3.zero, false)
		humanoid.Jump = false
		return
	end
	humanoid.PlatformStand = false
	if antiGravity then
		antiGravity.Enabled = false
	end
	local horizontal = steer(root, move * speed, (if grounded then GROUND_KEEP else AIR_KEEP) ^ (TICKS * dt))
	humanoid.WalkSpeed = horizontal.Magnitude
	humanoid:Move(if horizontal.Magnitude > 0.01 then horizontal.Unit else Vector3.zero, false)
	if grounded then
		stepUp(root, horizontal, dt)
	end
	local jump = (tonumber(player:GetAttribute("McRideJump")) or 0) * BLOCK
	if not space then
		lastJump = -math.huge
	end
	if space and jump > 0 and grounded and os.clock() - lastJump >= 0.5 then
		lastJump = os.clock()
		pcall(function()
			humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
		end)
		local velocity = root.AssemblyLinearVelocity
		root.AssemblyLinearVelocity = Vector3.new(velocity.X, math.sqrt(2 * workspace.Gravity * jump), velocity.Z)
	end
	humanoid.Jump = false
end

local function walk(humanoid: Humanoid, root: BasePart, free: boolean, dt: number)
	local mode = gameMode()
	local spectator = mode == "spectator"
	if spectator then
		flying = true -- spectators always fly (and go through blocks: their collision group, from the server)
	elseif mode ~= "creative" then
		flying = false
	end
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
	local shift = not free and keyDown(Enum.KeyCode.LeftShift, Enum.KeyCode.RightShift)
	local space = not free and keyDown(Enum.KeyCode.Space)
	local rideMode = player:GetAttribute("McRideMode")
	if type(rideMode) == "string" and humanoid.Health > 0 and not spectator then
		ride(humanoid, root, move, shift, space, rideMode, dt)
		return
	end
	local grounded = not spectator and onGround(root)
	if player:GetAttribute("McGround") ~= grounded then
		player:SetAttribute("McGround", grounded) -- (MinecraftClient: breaking is 5 x slower in the air)
	end
	if player:GetAttribute("McFlying") ~= flying then
		player:SetAttribute("McFlying", flying) -- (no fall damage while flying)
	end
	if flying and not spectator and grounded and not space and os.clock() - flyingSince > 0.3 then
		flying = false -- landed: Minecraft stops flying
	end
	sneaking = shift and not flying and fluidHere == nil
	-- sprinting: while Ctrl is held or after W twice, only walking forward (and not while sneaking)
	if ahead <= 0 or sneaking or free then
		tapSprint = false
	end
	sprinting = not free and (keyDown(Enum.KeyCode.LeftControl, Enum.KeyCode.RightControl) or tapSprint) and ahead > 0
		and not sneaking
	-- Minecraft: no sprinting with 3 drumsticks or less (survival / adventure; flying always)
	local playMode = gameMode()
	if sprinting and not flying and (playMode == "survival" or playMode == "adventure") and (tonumber(player:GetAttribute("McFood")) or 20) <= 6 then
		sprinting = false
		tapSprint = false
	end
	-- swimming (Minecraft's updateSwimming): starts sprinting with the eyes under water, goes on while sprinting in
	-- water (also at the surface); not in creative flight, not as a spectator
	if swimming then
		swimming = sprinting and fluidHere == "water" and not flying
	else
		swimming = sprinting and eyeFluid == "water" and fluidHere == "water" and not flying
	end
	humanoid.AutoRotate = false
	pcall(function()
		humanoid:SetStateEnabled(Enum.HumanoidStateType.Climbing, false) -- Minecraft climbs only ladders
	end)
	-- flying / in water or lava: no hip spring, no floor, no gravity - the speed below is all there is
	local fluid = if flying or spectator then nil else fluidHere
	humanoid.PlatformStand = flying or fluid ~= nil
	if antiGravity then
		antiGravity.Force = Vector3.new(0, root.AssemblyMass * workspace.Gravity, 0)
		antiGravity.Enabled = flying or fluid ~= nil
	end
	if fluid then
		local physics = FLUID[fluid] or FLUID.water
		local steps = TICKS * dt
		local keep = if sprinting or swimming then physics.sprintKeep else physics.keep
		-- horizontal: the speed it settles at = accel x keep / (1 - keep) (water 1.6, sprinting / swimming 3.5 blocks/s)
		local horizontal = steer(root, move * (FLUID_ACCEL * keep / (1 - keep) * TICKS * BLOCK), keep ^ steps)
		local velocity = root.AssemblyLinearVelocity
		local vy = velocity.Y / (TICKS * BLOCK) -- blocks per tick
		-- Space: up (jumpInLiquid), Shift: down (LocalPlayer.goDownInWater) - 0.04 blocks per tick each
		local up = (if space then FLUID_UP else 0) - (if shift then FLUID_UP else 0)
		local sink = if sprinting or swimming then 0 else physics.sink
		local target = (up * physics.vertical - sink) / (1 - physics.vertical)
		vy = target + (vy - target) * physics.vertical ^ steps
		if swimming then
			-- Player.travel: swimming goes up / down where he looks (stronger looking down)
			local lookY = -math.sin(pitch)
			local strength = if lookY < -0.2 then 0.085 else 0.06
			if lookY <= 0 or space or eyeFluid == "water" then
				vy += (lookY - vy) * (1 - (1 - strength) ^ steps)
			end
		end
		if space and fluid == "water" and canJumpOut(root, move) then
			vy = math.max(vy, OUT_OF_FLUID)
		end
		root.AssemblyLinearVelocity = Vector3.new(horizontal.X, vy * TICKS * BLOCK, horizontal.Z)
		humanoid:Move(Vector3.zero, false)
		humanoid.Jump = false
		return
	end
	if flying then
		local speed = FLY_SPEED * (if sprinting then 2 else 1)
		local horizontal = steer(root, move * speed, AIR_KEEP ^ (TICKS * dt))
		local wanted = ((if space then 1 else 0) - (if shift then 1 else 0)) * FLY_VERTICAL
		local velocity = root.AssemblyLinearVelocity
		local vertical = wanted + (velocity.Y - wanted) * FLY_VERTICAL_KEEP ^ (TICKS * dt)
		if math.abs(vertical) < 0.05 and wanted == 0 then
			vertical = 0
		end
		root.AssemblyLinearVelocity = Vector3.new(horizontal.X, vertical, horizontal.Z)
		humanoid:Move(Vector3.zero, false)
		humanoid.Jump = false
		return
	end
	local speed = (if sneaking then Character.SNEAK_SPEED elseif sprinting then Character.SPRINT_SPEED else Character.WALK_SPEED)
		* effectSpeed()
	if sneaking and grounded and move.Magnitude > 0 then
		groundParams.FilterDescendantsInstances = { root.Parent :: Instance }
		move = stayOnEdge(root, move, speed)
	end
	local horizontal = steer(root, move * speed, (if grounded then GROUND_KEEP else AIR_KEEP) ^ (TICKS * dt))
	-- climbing (Minecraft's LivingEntity.handleOnClimbable): sideways at most 0.15 blocks / tick, falling at most 0.15,
	-- walking into it / jumping = up with 0.2, sneaking = holding on
	local climbing = not spectator and onClimbable(root)
	if player:GetAttribute("McClimbing") ~= (if climbing then true else nil) then
		player:SetAttribute("McClimbing", if climbing then true else nil) -- (no fall damage: MinecraftClient)
	end
	if climbing then
		local limit = 0.15 * TICKS * BLOCK
		horizontal = Vector3.new(math.clamp(horizontal.X, -limit, limit), 0, math.clamp(horizontal.Z, -limit, limit))
		local vy = root.AssemblyLinearVelocity.Y
		if space or move.Magnitude > 0.1 then
			vy = 0.2 * TICKS * BLOCK
		elseif sneaking then
			vy = 0
		else
			vy = math.max(vy, -limit)
		end
		root.AssemblyLinearVelocity = Vector3.new(horizontal.X, vy, horizontal.Z)
	end
	-- the humanoid wants the same speed (it would brake against it otherwise)
	humanoid.WalkSpeed = horizontal.Magnitude
	humanoid:Move(if horizontal.Magnitude > 0.01 then horizontal.Unit else Vector3.zero, false)
	if grounded then
		stepUp(root, horizontal, dt)
	end
	-- Jumping like Minecraft: only with the feet on a block, held = again after landing, at most every 10 ticks;
	-- sprinting gives a push forward
	if not space then
		lastJump = -math.huge
	end
	if space and humanoid.Health > 0 and os.clock() - lastJump >= 0.5 and grounded then
		lastJump = os.clock()
		pcall(function()
			humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
		end)
		local velocity = root.AssemblyLinearVelocity
		local push = if sprinting then forward * SPRINT_JUMP else Vector3.zero
		-- jump boost: + 0.1 blocks / tick per level (Minecraft's getJumpBoostPower)
		local boost = if effects.jump_boost then 0.1 * ((tonumber(effects.jump_boost.amp) or 0) + 1) * TICKS * BLOCK else 0
		root.AssemblyLinearVelocity = Vector3.new(velocity.X + push.X, Character.JUMP_VELOCITY + boost, velocity.Z + push.Z)
	end
	-- levitation: up with 0.05 blocks / tick per level (Minecraft: vy += (target - vy) x 0.2 per tick, no gravity);
	-- slow falling: falling with 1/8 of the gravity
	if effects.levitation then
		local target = 0.05 * ((tonumber(effects.levitation.amp) or 0) + 1) * TICKS * BLOCK
		local velocity = root.AssemblyLinearVelocity
		local vy = target + (velocity.Y - target) * 0.8 ^ (TICKS * dt) + workspace.Gravity * dt
		root.AssemblyLinearVelocity = Vector3.new(velocity.X, vy, velocity.Z)
	elseif effects.slow_falling then
		local velocity = root.AssemblyLinearVelocity
		if velocity.Y < 0 then
			root.AssemblyLinearVelocity = Vector3.new(velocity.X, velocity.Y + workspace.Gravity * 0.875 * dt, velocity.Z)
		end
	end
	humanoid.Jump = false
end

local function isFlying(): boolean
	return flying
end
-- endregion

-- region camera
local cameraParams = RaycastParams.new()
cameraParams.FilterType = Enum.RaycastFilterType.Exclude

local function clip(from: Vector3, direction: Vector3, character: Model): number
	if gameMode() == "spectator" then
		return THIRD_DISTANCE -- (Minecraft: a spectator's camera goes through blocks)
	end
	local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
	cameraParams.FilterDescendantsInstances = if npcs then { character, npcs } else { character }
	local hit = workspace:Raycast(from, direction * THIRD_DISTANCE, cameraParams)
	return if hit then math.max(0, (hit.Position - from).Magnitude - 0.3) else THIRD_DISTANCE
end

-- how a body is shown: "all", "none" (first person / a spectator for the others), "head" (a spectator as other
-- spectators see him: only the head, see-through - like Minecraft)
local function showModel(model: Model, how: string)
	for _, item in ipairs(model:GetDescendants()) do
		if item:IsA("BasePart") or item:IsA("Decal") then
			local part = if item:IsA("Decal") then item.Parent else item
			local head = part ~= nil and (part.Name == "Head" or part.Name == "Hat")
			item.LocalTransparencyModifier = if how == "all" then 0 elseif how == "none" then 1 elseif head then 0.5 else 1
		end
	end
end

local function hideCharacter(character: Model, hidden: boolean)
	showModel(character, if hidden then "none" elseif gameMode() == "spectator" then "head" else "all")
end

-- the others: spectators only for spectators (Roblox players: their character's McGameMode from the server,
-- Minecraft players: their NPC's, from PlayerSync)
local function showOthers()
	local iAmSpectator = gameMode() == "spectator"
	local function apply(model: Model)
		local spectator = model:GetAttribute("McGameMode") == "spectator"
		showModel(model, if not spectator then "all" elseif iAmSpectator then "head" else "none")
		local humanoid = model:FindFirstChildOfClass("Humanoid")
		if humanoid then
			humanoid.DisplayDistanceType = if spectator and not iAmSpectator then Enum.HumanoidDisplayDistanceType.None
				else Enum.HumanoidDisplayDistanceType.Viewer
		end
	end
	for _, other in ipairs(Players:GetPlayers()) do
		if other ~= player and other.Character then
			apply(other.Character)
		end
	end
	local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
	if npcs then
		for _, folder in ipairs(npcs:GetChildren()) do
			for _, model in ipairs(folder:GetChildren()) do
				if model:IsA("Model") then
					apply(model)
				end
			end
		end
	end
end
task.spawn(function()
	while true do
		task.wait(0.25)
		pcall(showOthers)
	end
end)
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
			-- riding: sitting on it (the server sets McRideSeat = blocks above the feet)
			local seat = tonumber(if other == player then player:GetAttribute("McRideSeat") else character:GetAttribute("McRideSeat"))
			Character.ride(character, if seat then seat * Character.STUDS_PER_BLOCK else nil)
			local swims = if other == player then swimming else character:GetAttribute("McSwimming") == true
			apply(character, if swims then Character.SWIM_HEAD_PITCH
				elseif other == player then pitch else tonumber(character:GetAttribute("McPitch")) or 0)
		end
	end
	local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
	if npcs then
		for _, folder in ipairs(npcs:GetChildren()) do
			for _, model in ipairs(folder:GetChildren()) do
				if model:IsA("Model") then
					local seat = tonumber(model:GetAttribute("McRideSeat")) -- (a Minecraft player on a horse / in a boat)
					Character.ride(model, if seat then seat * Character.STUDS_PER_BLOCK else nil)
					apply(model, if model:GetAttribute("McSwimming") == true then Character.SWIM_HEAD_PITCH
						else tonumber(model:GetAttribute("McPitch")) or 0)
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
	flying = false
	-- the body turns with the view (a constraint - setting the root's CFrame every frame disturbed the physics)
	local attachment = Instance.new("Attachment")
	attachment.Name = "McYaw"
	attachment.Parent = root
	local align = Instance.new("AlignOrientation")
	align.Name = "McYaw"
	align.Mode = Enum.OrientationAlignmentMode.OneAttachment
	align.Attachment0 = attachment
	align.RigidityEnabled = true
	align.CFrame = CFrame.Angles(0, yaw, 0)
	align.Parent = root
	yawAlign = align
	local force = Instance.new("VectorForce") -- flying: no gravity
	force.Name = "McFly"
	force.Attachment0 = attachment
	force.RelativeTo = Enum.ActuatorRelativeTo.World
	force.ApplyAtCenterOfMass = true
	force.Enabled = false
	force.Parent = root
	antiGravity = force
	humanoid.Died:Connect(function()
		if animatedCharacter == character and animation then
			animation:die()
		end
		align.Enabled = false
		force.Enabled = false
		root.Anchored = true -- lies where it fell (the death animation tips it over, not the physics)
	end)
end
player.CharacterAdded:Connect(onCharacter)
if player.Character then
	task.spawn(onCharacter, player.Character)
end

-- region sleeping in a bed (Minecraft lays him down: the server sets McSleepAt = where his body lies)
local sleepState = { on = false, since = 0, gui = nil :: ScreenGui?, dark = nil :: Frame?, collide = true, asked = 0 }

local function leaveBed()
	-- "Leave Bed" (Minecraft's button): Minecraft gets him up next to the bed
	if sleepState.on and inventoryRemote and os.clock() - sleepState.asked > 0.5 then
		sleepState.asked = os.clock()
		inventoryRemote:FireServer("wake")
	end
end

local function sleepOverlay(show: boolean)
	if show and not sleepState.gui then
		local gui = Instance.new("ScreenGui")
		gui.Name = "McSleep"
		gui.IgnoreGuiInset = true
		gui.ResetOnSpawn = false
		gui.DisplayOrder = 4
		-- Minecraft darkens the screen while falling asleep (100 ticks, up to 220/255)
		local dark = Instance.new("Frame")
		dark.Name = "Dark"
		dark.Size = UDim2.fromScale(1, 1)
		dark.BackgroundColor3 = Color3.fromRGB(16, 16, 32)
		dark.BackgroundTransparency = 1
		dark.BorderSizePixel = 0
		dark.Parent = gui
		local button = Instance.new("TextButton")
		button.Name = "LeaveBed"
		button.AnchorPoint = Vector2.new(0.5, 1)
		button.Position = UDim2.new(0.5, 0, 1, -48)
		button.Size = UDim2.fromOffset(400, 40)
		button.BackgroundColor3 = Color3.fromRGB(111, 111, 111)
		button.BorderColor3 = Color3.new(0, 0, 0)
		button.BorderSizePixel = 2
		button.TextColor3 = Color3.new(1, 1, 1)
		button.Font = Enum.Font.Arcade
		button.TextSize = 22
		button.Text = "Leave Bed"
		button.Parent = gui
		button.Activated:Connect(leaveBed)
		gui.Parent = player:WaitForChild("PlayerGui")
		sleepState.gui = gui
		sleepState.dark = dark
	elseif not show and sleepState.gui then
		sleepState.gui:Destroy()
		sleepState.gui = nil
		sleepState.dark = nil
	end
end

-- every frame while asleep: the body lies in the bed (unanchored, so the others see it too), the view from the
-- pillow along the bed (Minecraft: toward its foot), the screen darkens
local function holdInBed(humanoid: Humanoid, root: BasePart, at: CFrame, camera: Camera)
	if not sleepState.on then
		sleepState.on = true
		sleepState.since = os.clock()
		sleepState.collide = root.CanCollide
		humanoid.PlatformStand = true
		root.CanCollide = false
		if yawAlign then
			yawAlign.Enabled = false
		end
		sleepOverlay(true)
	end
	if antiGravity then
		antiGravity.Force = Vector3.new(0, root.AssemblyMass * workspace.Gravity, 0)
		antiGravity.Enabled = true
	end
	root.CFrame = at
	root.AssemblyLinearVelocity = Vector3.zero
	root.AssemblyAngularVelocity = Vector3.zero
	local head = at.Position + at.UpVector * (Character.STUDS_PER_BLOCK * 0.6) + Vector3.new(0, 0.6, 0)
	camera.CFrame = CFrame.lookAt(head, head - at.UpVector)
	if sleepState.dark then
		sleepState.dark.BackgroundTransparency = 1 - 220 / 255 * math.clamp((os.clock() - sleepState.since) / 5, 0, 1)
	end
end

local function getUp(humanoid: Humanoid, root: BasePart)
	sleepState.on = false
	humanoid.PlatformStand = false
	root.CanCollide = sleepState.collide
	if yawAlign then
		yawAlign.Enabled = true
	end
	-- upright again, standing on the bed (Minecraft's place next to the bed comes as a teleport)
	root.CFrame = CFrame.new(root.Position + Vector3.new(0, Character.STUDS_PER_BLOCK * 0.7, 0)) * CFrame.Angles(0, yaw, 0)
	root.AssemblyLinearVelocity = Vector3.zero
	sleepOverlay(false)
end

UserInputService.InputBegan:Connect(function(input, processed)
	if not processed and sleepState.on and input.KeyCode == Enum.KeyCode.Space then
		leaveBed()
	end
end)
-- endregion

RunService:BindToRenderStep("MinecraftPlayer", Enum.RenderPriority.Camera.Value, function(dt)
	pollF5()
	local free = guiOpen() or sleepState.on
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
	local sleepAt = player:GetAttribute("McSleepAt")
	if typeof(sleepAt) == "CFrame" and humanoid.Health > 0 then
		holdInBed(humanoid, root, sleepAt, camera)
		lookAll(dt)
		return -- (asleep: no walking, no turning)
	elseif sleepState.on then
		getUp(humanoid, root)
	end
	senseFluids(root, eyeHeight)
	walk(humanoid, root, free, dt)
	if yawAlign and yawAlign.Parent == root and humanoid.Health > 0 then
		yawAlign.CFrame = CFrame.Angles(0, yaw, 0)
	end
	if animation and animatedCharacter == character then
		local velocity = root.AssemblyLinearVelocity
		animation:update(dt, { speed = Vector3.new(velocity.X, 0, velocity.Z).Magnitude, sneak = sneaking,
			swim = swimming })
	end
	lookAll(dt)

	-- the eyes (lower while sneaking, low while swimming, smoothly - like Minecraft)
	local wantedEye = if swimming then Character.SWIM_EYE_HEIGHT elseif sneaking then Character.SNEAK_EYE_HEIGHT
		else Character.EYE_HEIGHT
	eyeHeight += (wantedEye - eyeHeight) * (1 - math.exp(-dt * (if swimming then 4 else 12)))
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
	local blocking = player:GetAttribute("McBlocking") == true -- (a shield held up: MinecraftClient)
	if sneaking ~= sent.sneak or sprinting ~= sent.sprint or isFlying() ~= sent.flying or swimming ~= sent.swimming
		or blocking ~= sent.blocking or (math.abs(pitch - sent.pitch) > 0.03 and now - sent.at > SEND_EVERY) then
		sent.sneak, sent.sprint, sent.pitch, sent.at, sent.flying = sneaking, sprinting, pitch, now, isFlying()
		sent.swimming = swimming
		sent.blocking = blocking
		moveRemote:FireServer(sneaking, sprinting, math.floor(pitch * 100 + 0.5) / 100, isFlying(), swimming, blocking)
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
