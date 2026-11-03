--!strict
--[[
	MinecraftCharacter - the Minecraft player as a Roblox character (ModuleScript "MinecraftCharacter" in ReplicatedStorage)

	Every player looks like a Minecraft player: the Roblox players (StarterCharacter) and the NPCs of the Minecraft
	players. The measurements are Minecraft's own (PlayerModel: head 8x8x8 pixels, body 8x12x4, arms 4x12x4 or 3x12x4
	"slim", legs 4x12x4, the second skin layer 0.5 / 0.25 pixels bigger), drawn at Minecraft's 0.9375 scale with
	3 studs per block: one skin pixel = 0.17578125 studs. The hitbox is Minecraft's too (0.6 x 1.8 blocks).

	    local model = MinecraftCharacter.build({ slim = false })    -- the rig (parts, joints, Humanoid, Animator)
	    MinecraftCharacter.setShape(model, true)                   -- slim arms (the skin says which)
	    local animation = MinecraftCharacter.animate(model)         -- Minecraft's animations on it
	    animation:update(dt, { speed = 12.9, sneak = false })       -- every frame
	    animation:swing()                                           -- hit / build

	Joints like Minecraft: every body part hangs on its own at "ModelRoot" (the feet), just like in Minecraft all parts
	hang on the model root - the animations (made from Minecraft's code, see tools/make_animations.luau) move them
	exactly as Minecraft does. Skin: every face of every part has a Texture with the attribute McSkinFace = "u,v,w,h"
	(where it is in the 64x64 skin); the client puts the picture there (model attribute McSkin = which skin).
]]
local KeyframeSequenceProvider = game:GetService("KeyframeSequenceProvider")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

local Character = {}

local PIXEL = 3 / 16 * 0.9375 -- studs per skin pixel
Character.PIXEL = PIXEL
Character.STUDS_PER_BLOCK = 3
Character.HITBOX = Vector3.new(1.8, 5.4, 1.8) -- Minecraft: 0.6 x 1.8 x 0.6 blocks
--[[
	The root part IS Minecraft's hitbox (almost from the feet up): at an edge it lies on the block as long as any part
	of it is over the block - like Minecraft. (With Roblox's usual hip height of the legs only the middle under the
	player counts: at an edge the legs sank into the block.)
	A tiny hip height stays (0.1 studs = 1/30 block): the Humanoid holds the box just above the ground and walks and
	stops it itself. With 0 the box lay on the ground, the Humanoid lost the ground now and then and the player slid.
]]
Character.FOOT_GAP = 0.1
Character.HIP_HEIGHT = Character.FOOT_GAP
Character.ROOT_SIZE = Vector3.new(1.8, 5.4 - Character.FOOT_GAP, 1.8) -- the top stays at 1.8 blocks
Character.ROOT_HEIGHT = Character.FOOT_GAP + (5.4 - Character.FOOT_GAP) / 2 -- middle of the root part above the feet
Character.EYE_HEIGHT = 1.62 * 3 -- Minecraft's eyes: 1.62 blocks, sneaking 1.27
Character.SNEAK_EYE_HEIGHT = 1.27 * 3
-- Minecraft's movement in studs (blocks x 3): walk 4.317, sprint 5.612, sneak 1.295 blocks/s, jump 1.2522 blocks
Character.WALK_SPEED = 4.317 * 3
Character.SPRINT_SPEED = 5.612 * 3
Character.SNEAK_SPEED = 1.295 * 3
Character.JUMP_HEIGHT = 1.2522 * 3
-- Gravity so that a jump takes as long as in Minecraft (top after 6 ticks, down after 12): 83.5 studs/s² - falls of
-- 3 / 10 / 20 blocks then take 0.46 / 0.85 / 1.2 s like in Minecraft (0.45 / 0.85 / 1.2)
Character.GRAVITY = 83.5
Character.JUMP_VELOCITY = math.sqrt(2 * 83.5 * 1.2522 * 3) -- studs/s straight up at the start of a jump

-- region the model
--[[
	Minecraft model space: x to the model's left, y DOWN, z backwards (front = -z), in pixels; the feet are at y 24.
	Roblox (character space, front = -z, y up, feet = 0): (-x, 24 - y, z) * PIXEL.
	box = {x, y, z, w, h, d} relative to the pivot (the joint), uv = where the box is in the skin.
]]
type Box = { x: number, y: number, z: number, w: number, h: number, d: number }
type PartSpec = {
	name: string, joint: string, pivot: { number }, box: Box, slimBox: Box?, uv: { number },
	layer: string, layerUv: { number }, grow: number, color: Color3,
}

local PARTS: { PartSpec } = {
	{ name = "Head", joint = "Neck", pivot = { 0, 0, 0 }, box = { x = -4, y = -8, z = -4, w = 8, h = 8, d = 8 },
		uv = { 0, 0 }, layer = "Hat", layerUv = { 32, 0 }, grow = 0.5, color = Color3.fromRGB(178, 128, 104) },
	{ name = "Body", joint = "BodyJoint", pivot = { 0, 0, 0 }, box = { x = -4, y = 0, z = -2, w = 8, h = 12, d = 4 },
		uv = { 16, 16 }, layer = "Jacket", layerUv = { 16, 32 }, grow = 0.25, color = Color3.fromRGB(0, 168, 168) },
	{ name = "RightArm", joint = "RightShoulder", pivot = { -5, 2, 0 }, box = { x = -3, y = -2, z = -2, w = 4, h = 12, d = 4 },
		slimBox = { x = -2, y = -2, z = -2, w = 3, h = 12, d = 4 },
		uv = { 40, 16 }, layer = "RightSleeve", layerUv = { 40, 32 }, grow = 0.25, color = Color3.fromRGB(178, 128, 104) },
	{ name = "LeftArm", joint = "LeftShoulder", pivot = { 5, 2, 0 }, box = { x = -1, y = -2, z = -2, w = 4, h = 12, d = 4 },
		slimBox = { x = -1, y = -2, z = -2, w = 3, h = 12, d = 4 },
		uv = { 32, 48 }, layer = "LeftSleeve", layerUv = { 48, 48 }, grow = 0.25, color = Color3.fromRGB(178, 128, 104) },
	{ name = "RightLeg", joint = "RightHip", pivot = { -1.9, 12, 0 }, box = { x = -2, y = 0, z = -2, w = 4, h = 12, d = 4 },
		uv = { 0, 16 }, layer = "RightPants", layerUv = { 0, 32 }, grow = 0.25, color = Color3.fromRGB(70, 60, 150) },
	{ name = "LeftLeg", joint = "LeftHip", pivot = { 1.9, 12, 0 }, box = { x = -2, y = 0, z = -2, w = 4, h = 12, d = 4 },
		uv = { 16, 48 }, layer = "LeftPants", layerUv = { 0, 48 }, grow = 0.25, color = Color3.fromRGB(70, 60, 150) },
}
Character.PARTS = PARTS

local function toRoblox(x: number, y: number, z: number): Vector3
	return Vector3.new(-x, 24 - y, z) * PIXEL
end

--[[
	The six faces of a box in the skin (Minecraft's cube layout, u/v = the corner of the box's area, w h d its size):
	    [   ][top][bottom][    ]        top    = u+d,     v,   w x d
	    [right][front][left][back]      right  = u,       v+d, d x h   (the character's right side = Roblox +X)
	                                    front  = u+d,     v+d, w x h   (Roblox -Z)
	                                    left   = u+d+w,   v+d, d x h   (Roblox -X)
	                                    back   = u+2d+w,  v+d, w x h   (Roblox +Z)
	                                    bottom = u+d+w,   v,   w x d
	Seen from outside, every side face shows its area the right way round (Roblox textures do the same).
]]
local function faceRegions(u: number, v: number, w: number, h: number, d: number)
	return { -- by face name
		Top = { u + d, v, w, d },
		Bottom = { u + d + w, v, w, d },
		Right = { u, v + d, d, h },
		Front = { u + d, v + d, w, h },
		Left = { u + d + w, v + d, d, h },
		Back = { u + 2 * d + w, v + d, w, h },
	}
end
Character.faceRegions = faceRegions

local FACES = { Enum.NormalId.Top, Enum.NormalId.Bottom, Enum.NormalId.Right, Enum.NormalId.Front, Enum.NormalId.Left,
	Enum.NormalId.Back }

--- Sizes / textures of one body part (and its second layer) for a box - also used to switch slim <-> wide arms.
local function shapePart(part: BasePart, layerPart: BasePart, motor: Motor6D, spec: PartSpec, box: Box)
	local pivot = toRoblox(spec.pivot[1], spec.pivot[2], spec.pivot[3])
	local centerModel = { spec.pivot[1] + box.x + box.w / 2, spec.pivot[2] + box.y + box.h / 2, spec.pivot[3] + box.z + box.d / 2 }
	local center = toRoblox(centerModel[1], centerModel[2], centerModel[3])
	part.Size = Vector3.new(box.w, box.h, box.d) * PIXEL
	layerPart.Size = Vector3.new(box.w + 2 * spec.grow, box.h + 2 * spec.grow, box.d + 2 * spec.grow) * PIXEL
	motor.C0 = CFrame.new(pivot)
	motor.C1 = CFrame.new(pivot - center)
	local function texturize(target: BasePart, uv: { number })
		local regions = faceRegions(uv[1], uv[2], box.w, box.h, box.d)
		for _, face in ipairs(FACES) do
			local texture = target:FindFirstChild("Skin" .. face.Name) :: Texture?
			if texture then
				local region = regions[face.Name]
				texture:SetAttribute("McSkinFace", table.concat(region, ","))
				-- one picture = the whole face
				local size = target.Size
				local faceSize = if face == Enum.NormalId.Top or face == Enum.NormalId.Bottom
					then Vector2.new(size.X, size.Z)
					elseif face == Enum.NormalId.Left or face == Enum.NormalId.Right then Vector2.new(size.Z, size.Y)
					else Vector2.new(size.X, size.Y)
				texture.StudsPerTileU = faceSize.X
				texture.StudsPerTileV = faceSize.Y
			end
		end
	end
	texturize(part, spec.uv)
	texturize(layerPart, spec.layerUv)
end

local function skinTextures(part: BasePart)
	for _, face in ipairs(FACES) do
		local texture = Instance.new("Texture")
		texture.Name = "Skin" .. face.Name
		texture.Face = face
		texture.Parent = part
	end
end

--- The rig: Humanoid (R15 with Minecraft's hip height), HumanoidRootPart (the hitbox), ModelRoot at the feet, 6 body
--- parts + 6 second-layer parts, Motor6Ds named like the joints in the animations.
function Character.build(options: { slim: boolean?, name: string? }?): Model
	local slim = options and options.slim == true
	local model = Instance.new("Model")
	model.Name = options and options.name or "MinecraftCharacter"

	local root = Instance.new("Part")
	root.Name = "HumanoidRootPart"
	root.Size = Character.ROOT_SIZE
	root.Transparency = 1
	root.CanCollide = true
	root.CanQuery = false
	root.CanTouch = true
	root.TopSurface = Enum.SurfaceType.Smooth
	root.BottomSurface = Enum.SurfaceType.Smooth
	root.CFrame = CFrame.new(0, Character.ROOT_HEIGHT, 0)
	-- no friction: Minecraft's movement (MinecraftPlayer) sets the speed itself - a box resting on the edge of a block
	-- must never stick to it (it did: standing on placed blocks, walking sometimes did nothing)
	pcall(function()
		root.CustomPhysicalProperties = PhysicalProperties.new(0.7, 0, 0, 100, 1)
	end)
	root.Parent = model
	model.PrimaryPart = root

	local modelRoot = Instance.new("Part")
	modelRoot.Name = "ModelRoot"
	modelRoot.Size = Vector3.one * 0.2
	modelRoot.Transparency = 1
	modelRoot.CanCollide = false
	modelRoot.CanQuery = false
	modelRoot.CanTouch = false
	modelRoot.Massless = true
	modelRoot.CFrame = CFrame.new(0, 0, 0)
	modelRoot.Parent = model
	local rootJoint = Instance.new("Motor6D")
	rootJoint.Name = "Root"
	rootJoint.Part0 = root
	rootJoint.Part1 = modelRoot
	rootJoint.C0 = CFrame.new(0, -Character.ROOT_HEIGHT, 0)
	rootJoint.Parent = root

	for _, spec in ipairs(PARTS) do
		local box = if slim and spec.slimBox then spec.slimBox else spec.box
		local part = Instance.new("Part")
		part.Name = spec.name
		part.Color = spec.color
		part.Material = Enum.Material.SmoothPlastic
		part.TopSurface = Enum.SurfaceType.Smooth
		part.BottomSurface = Enum.SurfaceType.Smooth
		part.CanCollide = false
		part.CanTouch = false
		part.Massless = true
		part.Parent = model
		skinTextures(part)
		local layer = Instance.new("Part")
		layer.Name = spec.layer
		layer.Transparency = 1 -- only the picture (it has holes)
		layer.CanCollide = false
		layer.CanQuery = false
		layer.CanTouch = false
		layer.Massless = true
		layer.CastShadow = false
		layer.Parent = model
		skinTextures(layer)
		local weld = Instance.new("Weld")
		weld.Name = "LayerWeld"
		weld.Part0 = part
		weld.Part1 = layer
		weld.Parent = layer
		local motor = Instance.new("Motor6D")
		motor.Name = spec.joint
		motor.Part0 = modelRoot
		motor.Part1 = part
		motor.Parent = part
		shapePart(part, layer, motor, spec, box)
		part.CFrame = modelRoot.CFrame * motor.C0 * motor.C1:Inverse()
		layer.CFrame = part.CFrame
	end

	local humanoid = Instance.new("Humanoid")
	humanoid.RigType = Enum.HumanoidRigType.R15
	humanoid.HipHeight = Character.HIP_HEIGHT
	humanoid.AutomaticScalingEnabled = false
	humanoid.BreakJointsOnDeath = false
	humanoid.RequiresNeck = false
	humanoid.UseJumpPower = false
	humanoid.JumpHeight = Character.JUMP_HEIGHT
	humanoid.WalkSpeed = Character.WALK_SPEED
	humanoid.MaxHealth = 20
	humanoid.Health = 20
	humanoid.Parent = model
	local animator = Instance.new("Animator")
	animator.Parent = humanoid

	model:SetAttribute("McSlim", slim)
	return model
end

--- Slim (3 pixels) or wide (4 pixels) arms - the skin decides.
function Character.setShape(model: Model, slim: boolean)
	model:SetAttribute("McSlim", slim)
	for _, spec in ipairs(PARTS) do
		if spec.slimBox then
			local part = model:FindFirstChild(spec.name) :: BasePart?
			local layer = model:FindFirstChild(spec.layer) :: BasePart?
			local motor = part and part:FindFirstChild(spec.joint) :: Motor6D?
			if part and layer and motor then
				shapePart(part, layer, motor, spec, if slim then spec.slimBox else spec.box)
			end
		end
	end
end

--- Root part height over the feet of any humanoid (R15: hip height + half the root part; R6: legs 2 studs).
function Character.rootHeightOf(humanoid: Humanoid, root: BasePart): number
	if humanoid.RigType == Enum.HumanoidRigType.R6 then
		return root.Size.Y / 2 + 2
	end
	return root.Size.Y / 2 + humanoid.HipHeight
end
-- endregion

-- region animations
-- Uploaded animations (tools/upload_animations.py writes the ids); in Studio the KeyframeSequences in
-- ReplicatedStorage.MinecraftAnimations work too, before they are uploaded.
local registered: { [string]: string } = {}
local function animationId(name: string): string?
	local idsModule = ReplicatedStorage:FindFirstChild("MinecraftAnimationIds")
	if idsModule and idsModule:IsA("ModuleScript") then
		local ok, ids = pcall(require, idsModule)
		if ok and type(ids) == "table" and type(ids[name]) == "number" and ids[name] > 0 then
			return "rbxassetid://" .. tostring(ids[name])
		end
	end
	if registered[name] then
		return registered[name]
	end
	if RunService:IsStudio() then
		local folder = ReplicatedStorage:FindFirstChild("MinecraftAnimations")
		local sequence = folder and folder:FindFirstChild(name)
		if sequence and sequence:IsA("KeyframeSequence") then
			local ok, id = pcall(function()
				return KeyframeSequenceProvider:RegisterKeyframeSequence(sequence)
			end)
			if ok and type(id) == "string" then
				registered[name] = id
				return id
			end
		end
	end
	return nil
end
Character.animationId = animationId

Character.ANIMATIONS = { "idle", "walk", "sneak", "sneak_walk", "swing", "sneak_swing", "death" }

export type Animation = {
	update: (self: Animation, dt: number, state: { speed: number, sneak: boolean? }) -> (),
	swing: (self: Animation) -> (),
	die: (self: Animation) -> (),
	destroy: (self: Animation) -> (),
}

local Animation = {}
Animation.__index = Animation

--[[
	Plays Minecraft's animations on a character. Minecraft's walking: the amount a = min(blocks per tick x 4, 1) follows
	the speed (40 % per tick), the limbs swing with amplitude a and the cycle runs a times as fast - the animation
	"walk" is made for a = 1 (sprinting), so it plays with weight a and speed a over "idle".
]]
function Character.animate(model: Model)
	local humanoid = model:FindFirstChildOfClass("Humanoid")
	local animator = humanoid and humanoid:FindFirstChildOfClass("Animator")
	local self = setmetatable({ tracks = {}, amount = 0, base = nil, move = nil, dead = false }, Animation)
	if not animator then
		return self
	end
	for _, name in ipairs(Character.ANIMATIONS) do
		local id = animationId(name)
		if id then
			local animation = Instance.new("Animation")
			animation.AnimationId = id
			local ok, track = pcall(function()
				return (animator :: Animator):LoadAnimation(animation)
			end)
			if ok and track then
				self.tracks[name] = track
			end
		end
	end
	return self
end

function Animation:update(dt: number, state: { speed: number, sneak: boolean? })
	if self.dead then
		return
	end
	local tracks = self.tracks
	-- studs/s -> blocks per tick x 4 (Minecraft's walk animation speed), smoothed like Minecraft (40 % per tick)
	local target = math.min(state.speed / 3 / 20 * 4, 1)
	self.amount += (target - self.amount) * (1 - math.exp(-dt * 10.2))
	if self.amount < 0.002 then
		self.amount = 0
	end
	local base = if state.sneak then "sneak" else "idle"
	local move = if state.sneak then "sneak_walk" else "walk"
	if base ~= self.base then
		if self.base and tracks[self.base] then
			tracks[self.base]:Stop(0.1)
		end
		if tracks[base] then
			tracks[base]:Play(0.1)
		end
		self.base = base
	end
	if move ~= self.move then
		if self.move and tracks[self.move] then
			tracks[self.move]:Stop(0.1)
		end
		if tracks[move] then
			tracks[move]:Play(0.1)
		end
		self.move = move
	end
	local track = tracks[move]
	if track then
		track:AdjustWeight(math.max(self.amount, 0.001), 0)
		track:AdjustSpeed(math.max(self.amount, 0.001))
	end
	self.sneaking = state.sneak == true
end

function Animation:swing()
	local track = self.tracks[if self.sneaking then "sneak_swing" else "swing"]
	if track and not self.dead then
		if track.IsPlaying then
			track.TimePosition = 0 -- swinging again (breaking a block: Minecraft starts the swing anew every 3 ticks)
		else
			track:Play(0.02)
		end
	end
end

function Animation:die()
	self.dead = true
	for name, track in pairs(self.tracks) do
		if name ~= "death" then
			track:Stop(0.1)
		end
	end
	if self.tracks.death then
		self.tracks.death:Play(0.05)
	end
end

function Animation:destroy()
	for _, track in pairs(self.tracks) do
		track:Stop(0)
		track:Destroy()
	end
	table.clear(self.tracks)
end
-- endregion

-- region getting hurt
--- Minecraft tints a hurt player red for half a second - everybody sees it.
function Character.flashRed(model: Model)
	local highlight = model:FindFirstChild("McHurt") :: Highlight?
	if not highlight then
		local created = Instance.new("Highlight")
		created.Name = "McHurt"
		created.FillColor = Color3.fromRGB(255, 0, 0)
		created.FillTransparency = 0.5
		created.OutlineTransparency = 1
		created.DepthMode = Enum.HighlightDepthMode.Occluded
		created.Adornee = model
		created.Parent = model
		highlight = created
	end
	local token = (tonumber(model:GetAttribute("McHurtAt")) or 0) + 1
	model:SetAttribute("McHurtAt", token)
	task.delay(0.5, function()
		if model:GetAttribute("McHurtAt") == token and highlight and highlight.Parent then
			highlight:Destroy()
		end
	end)
end
-- endregion

-- region looking up / down
--- The head follows the look (Minecraft: head.xRot = pitch). pitch in radians, + = looking down.
function Character.look(model: Model, pitch: number)
	local head = model:FindFirstChild("Head")
	local neck = head and head:FindFirstChild("Neck") :: Motor6D?
	if neck then
		neck.C0 = CFrame.new(neck.C0.Position) * CFrame.Angles(-pitch, 0, 0)
	end
end
-- endregion

return Character
