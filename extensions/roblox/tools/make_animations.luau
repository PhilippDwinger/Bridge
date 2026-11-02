--[[
	Makes the Minecraft animations for the MinecraftWorld game as Roblox KeyframeSequences (.rbxm files).

	    lune run extensions/roblox/tools/make_animations.luau

	Writes extensions/roblox/examples/MinecraftWorld/animations/<name>.rbxm (Rojo puts them into
	ReplicatedStorage.MinecraftAnimations). tools/upload_animations.py uploads them as Roblox animations.

	Nothing here is invented: the movements are Minecraft's own code (26.3, HumanoidModel.setupAnim,
	setupAttackAnimation, AnimationUtils.bobModelPart, LivingEntityRenderer.setupRotations, AvatarRenderer offset),
	sampled into keyframes:
	- walking: legs cos(p 0.6662) 1.4 a, arms cos(p 0.6662 + pi) a; p advances a per tick, a = min(blocks/tick x 4, 1).
	  Made for a = 1 - the game plays it with weight and speed a.
	- breathing (idle): arms zRot +- (cos(age 0.09) 0.05 + 0.05), xRot +- sin(age 0.067) 0.05.
	- sneaking: body xRot 0.5, arms xRot + 0.4, legs z + 4, head y + 4.2, body / arms y + 3.2, everything 2 px lower.
	- hitting (6 ticks): body yRot sin(sqrt(t) 2 pi) 0.2, the arms go round with it, the right arm
	  xRot - (sin(outQuart(t) pi) 1.2 + sin(t pi) 0.525), zRot - sin(t pi) 0.4.
	- dying: the whole body falls to its side, sqrt((ticks - 1) / 12.5) x 90 degrees.

	Minecraft model space -> Roblox: x and y flipped (Minecraft: y down, x to the model's left), so a Minecraft rotation
	(xRot, yRot, zRot, applied Z Y X) is Roblox CFrame.Angles(0, 0, zRot) * CFrame.Angles(0, -yRot, 0) *
	CFrame.Angles(-xRot, 0, 0), and a move (dx, dy, dz) pixels is (-dx, -dy, dz) * PIXEL.
]]
local fs = require("@lune/fs")
local process = require("@lune/process")
local roblox = require("@lune/roblox")
local Instance, CFrame, Enum = roblox.Instance, roblox.CFrame, roblox.Enum

local PIXEL = 3 / 16 * 0.9375
local HIP_HEIGHT = 12 * PIXEL
local TICK = 1 / 20
local CYCLE_TICKS = 2 * math.pi / 0.6662 -- one walking cycle at a = 1 (9.43 ticks)

local OUT = (process.args[1] or "extensions/roblox/examples/MinecraftWorld/animations")

local LIMBS = { "Head", "Body", "RightArm", "LeftArm", "RightLeg", "LeftLeg" }
local DEFAULT = { -- Minecraft's PartPose of each part (pixels)
	Head = { 0, 0, 0 }, Body = { 0, 0, 0 }, RightArm = { -5, 2, 0 }, LeftArm = { 5, 2, 0 },
	RightLeg = { -1.9, 12, 0 }, LeftLeg = { 1.9, 12, 0 },
}

type Part = { x: number, y: number, z: number, xRot: number, yRot: number, zRot: number }
type Pose = { [string]: Part }

local function fresh(): Pose
	local pose = {}
	for _, name in ipairs(LIMBS) do
		local d = DEFAULT[name]
		pose[name] = { x = d[1], y = d[2], z = d[3], xRot = 0, yRot = 0, zRot = 0 }
	end
	pose.ModelRoot = { x = 0, y = 0, z = 0, xRot = 0, yRot = 0, zRot = 0 } -- already in Roblox terms (see below)
	return pose
end

-- region Minecraft's code (HumanoidModel.setupAnim with an empty hand, no item, not riding / swimming)
local function walk(pose: Pose, position: number, amount: number)
	pose.RightArm.xRot = math.cos(position * 0.6662 + math.pi) * 2 * amount * 0.5
	pose.LeftArm.xRot = math.cos(position * 0.6662) * 2 * amount * 0.5
	pose.RightLeg.xRot = math.cos(position * 0.6662) * 1.4 * amount
	pose.LeftLeg.xRot = math.cos(position * 0.6662 + math.pi) * 1.4 * amount
	pose.RightLeg.yRot, pose.LeftLeg.yRot = 0.005, -0.005
	pose.RightLeg.zRot, pose.LeftLeg.zRot = 0.005, -0.005
end

local function outQuart(t: number): number
	return 1 - (1 - t) ^ 4
end

-- setupAttackAnimation, right hand, "whack" (t = 0 .. 1 over the 6 ticks of a swing), head looking straight
local function attack(pose: Pose, t: number)
	if t <= 0 then
		return
	end
	local body = pose.Body
	body.yRot = math.sin(math.sqrt(t) * math.pi * 2) * 0.2
	local right, left = pose.RightArm, pose.LeftArm
	right.z = math.sin(body.yRot) * 5
	right.x = -math.cos(body.yRot) * 5
	left.z = -math.sin(body.yRot) * 5
	left.x = math.cos(body.yRot) * 5
	right.yRot += body.yRot
	left.yRot += body.yRot
	left.xRot += body.yRot
	local swing = math.sin(outQuart(t) * math.pi)
	local headPart = math.sin(t * math.pi) * -(0 - 0.7) * 0.75
	right.xRot -= swing * 1.2 + headPart
	right.yRot += body.yRot * 2
	right.zRot += math.sin(t * math.pi) * -0.4
end

local function crouch(pose: Pose)
	pose.Body.xRot = 0.5
	pose.RightArm.xRot += 0.4
	pose.LeftArm.xRot += 0.4
	pose.RightLeg.z += 4
	pose.LeftLeg.z += 4
	pose.Head.y += 4.2
	pose.Body.y += 3.2
	pose.LeftArm.y += 3.2
	pose.RightArm.y += 3.2
	pose.ModelRoot.y = -2 * PIXEL -- AvatarRenderer.getRenderOffset: crouching = 2 pixels lower (Roblox studs, up = +)
end

-- AnimationUtils.bobModelPart: the arms "breathe". The two frequencies are moved a tiny bit (0.0898 / 0.0673 instead of
-- 0.09 / 0.067) so that the loop of 14 s has whole cycles (4 and 3).
local BOB_LOOP = 14
local BOB_A = 4 * 2 * math.pi / (BOB_LOOP * 20)
local BOB_B = 3 * 2 * math.pi / (BOB_LOOP * 20)
local function bob(pose: Pose, age: number?)
	local z, x
	if age then
		z = math.cos(age * BOB_A) * 0.05 + 0.05
		x = math.sin(age * BOB_B) * 0.05
	else
		z, x = 0.05, 0 -- the average (while walking the breathing is too small to see)
	end
	pose.RightArm.zRot += z
	pose.RightArm.xRot += x
	pose.LeftArm.zRot -= z
	pose.LeftArm.xRot -= x
end
-- endregion

-- region Minecraft -> Roblox
local function cframeOf(name: string, part: Part)
	if name == "ModelRoot" then
		return CFrame.new(part.x, part.y, part.z) * CFrame.Angles(part.xRot, part.yRot, part.zRot)
	end
	local d = DEFAULT[name]
	local move = CFrame.new(-(part.x - d[1]) * PIXEL, -(part.y - d[2]) * PIXEL, (part.z - d[3]) * PIXEL)
	return move * CFrame.Angles(0, 0, part.zRot) * CFrame.Angles(0, -part.yRot, 0) * CFrame.Angles(-part.xRot, 0, 0)
end

type Spec = { name: string, length: number, rate: number, loop: boolean, priority: any, parts: { string },
	at: (time: number) -> Pose, hold: number? }

local function sequence(spec: Spec)
	local kfs = Instance.new("KeyframeSequence")
	kfs.Name = spec.name
	kfs.Loop = spec.loop
	kfs.Priority = spec.priority
	pcall(function()
		kfs.AuthoredHipHeight = HIP_HEIGHT
	end)
	local steps = math.max(1, math.round(spec.length * spec.rate))
	local times = {}
	for i = 0, steps do
		table.insert(times, spec.length * i / steps)
	end
	if spec.hold then
		table.insert(times, spec.hold)
	end
	local animated = {}
	for _, name in ipairs(spec.parts) do
		animated[name] = true
	end
	for _, time in ipairs(times) do
		local pose = spec.at(math.min(time, spec.length))
		local keyframe = Instance.new("Keyframe")
		keyframe.Time = time
		keyframe.Parent = kfs
		local rootPose = Instance.new("Pose")
		rootPose.Name = "HumanoidRootPart"
		rootPose.Weight = 0
		rootPose.Parent = keyframe
		local modelPose = Instance.new("Pose")
		modelPose.Name = "ModelRoot"
		modelPose.Weight = if animated.ModelRoot then 1 else 0
		modelPose.CFrame = if animated.ModelRoot then cframeOf("ModelRoot", pose.ModelRoot) else CFrame.new()
		modelPose.EasingStyle = Enum.PoseEasingStyle.Linear
		modelPose.Parent = rootPose
		for _, name in ipairs(LIMBS) do
			if animated[name] then
				local limb = Instance.new("Pose")
				limb.Name = name
				limb.Weight = 1
				limb.CFrame = cframeOf(name, pose[name])
				limb.EasingStyle = Enum.PoseEasingStyle.Linear
				limb.EasingDirection = Enum.PoseEasingDirection.In
				limb.Parent = modelPose
			end
		end
	end
	return kfs
end
-- endregion

local ALL = { "ModelRoot", "Head", "Body", "RightArm", "LeftArm", "RightLeg", "LeftLeg" }
local SPECS: { Spec } = {
	{ name = "idle", length = BOB_LOOP, rate = 10, loop = true, priority = Enum.AnimationPriority.Idle, parts = ALL,
		at = function(time)
			local pose = fresh()
			bob(pose, time * 20)
			return pose
		end },
	{ name = "walk", length = CYCLE_TICKS * TICK, rate = 60, loop = true, priority = Enum.AnimationPriority.Movement,
		parts = { "RightArm", "LeftArm", "RightLeg", "LeftLeg" },
		at = function(time)
			local pose = fresh()
			walk(pose, time * 20, 1)
			bob(pose, nil)
			return pose
		end },
	{ name = "sneak", length = BOB_LOOP, rate = 10, loop = true, priority = Enum.AnimationPriority.Idle, parts = ALL,
		at = function(time)
			local pose = fresh()
			crouch(pose)
			bob(pose, time * 20)
			return pose
		end },
	{ name = "sneak_walk", length = CYCLE_TICKS * TICK, rate = 60, loop = true, priority = Enum.AnimationPriority.Movement,
		parts = { "RightArm", "LeftArm", "RightLeg", "LeftLeg" },
		at = function(time)
			local pose = fresh()
			walk(pose, time * 20, 1)
			crouch(pose)
			bob(pose, nil)
			return pose
		end },
	{ name = "swing", length = 6 * TICK, rate = 60, loop = false, priority = Enum.AnimationPriority.Action,
		parts = { "Body", "RightArm", "LeftArm" },
		at = function(time)
			local pose = fresh()
			attack(pose, time / (6 * TICK))
			bob(pose, nil)
			return pose
		end },
	{ name = "sneak_swing", length = 6 * TICK, rate = 60, loop = false, priority = Enum.AnimationPriority.Action,
		parts = { "Body", "RightArm", "LeftArm" },
		at = function(time)
			local pose = fresh()
			attack(pose, time / (6 * TICK))
			crouch(pose)
			bob(pose, nil)
			return pose
		end },
	{ name = "death", length = 13.5 * TICK, rate = 40, loop = false, priority = Enum.AnimationPriority.Action4,
		parts = { "ModelRoot" }, hold = 6,
		at = function(time)
			local pose = fresh()
			local ticks = time * 20
			local f = math.sqrt(math.clamp((ticks - 1) / 20 * 1.6, 0, 1))
			pose.ModelRoot.zRot = f * math.pi / 2 -- falls onto its left side, like Minecraft
			return pose
		end },
}

fs.writeDir(OUT)
for _, spec in ipairs(SPECS) do
	local kfs = sequence(spec)
	fs.writeFile(OUT .. "/" .. spec.name .. ".rbxm", roblox.serializeModel({ kfs }))
	print(string.format("%-12s %5.2f s  %3d keyframes  %s", spec.name, spec.hold or spec.length, #kfs:GetChildren(),
		if spec.loop then "loop" else "once"))
end
