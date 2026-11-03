--[[
	MinecraftCharacter + the Minecraft animations (no server needed):

	    lune run test_character.luau

	The rig has Minecraft's measurements, the skin faces are where Minecraft's skin layout has them, slim arms switch,
	and the animations (made by tools/make_animations.luau from Minecraft's code) move the parts like Minecraft.
]]
local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")
local roblox = require("@lune/roblox")
local shim = require("./roblox_shim")
local CFrame, Vector3 = roblox.CFrame, roblox.Vector3

shim.services.KeyframeSequenceProvider = {}
shim.services.ReplicatedStorage = { FindFirstChild = function()
	return nil
end }
local env = setmetatable({ game = game, Instance = roblox.Instance, Vector3 = Vector3, CFrame = CFrame, Enum = roblox.Enum,
	Color3 = roblox.Color3, Vector2 = roblox.Vector2, PhysicalProperties = roblox.PhysicalProperties, task = task },
	{ __index = _G })
local Character = luau.load(fs.readFile("../examples/MinecraftWorld/MinecraftCharacter.luau"), { environment = env })()

local results = { ok = 0, fail = 0 }
local function check(name, condition, info)
	if condition then
		results.ok += 1
		print("  OK    " .. name)
	else
		results.fail += 1
		print("  FAIL  " .. name .. "  " .. tostring(info))
	end
end
local function near(a, b, eps)
	return math.abs(a - b) < (eps or 1e-3)
end

local P = Character.PIXEL
local model = Character.build({ name = "Steve" })
local root = model:FindFirstChild("HumanoidRootPart")
local humanoid = model:FindFirstChildOfClass("Humanoid")
check("Minecraft's scale: 1 skin pixel = 3/16 * 0.9375 studs", near(P, 0.17578125))
check("hitbox 0.6 x 1.8 blocks: the root part IS the hitbox (0.1 hip height to the ground, top at 5.4 studs)",
	near(root.Size.X, 1.8) and near(humanoid.HipHeight + root.Size.Y, 5.4) and near(humanoid.HipHeight, 0.1)
	and near(root.CFrame.Position.Y, 2.75), tostring(root.Size))
check("Humanoid like Minecraft: 20 HP, jump 1.25 blocks, walk 4.317 blocks/s, joints stay on death",
	humanoid.MaxHealth == 20 and near(humanoid.JumpHeight, 3.7566) and near(humanoid.WalkSpeed, 12.951)
	and humanoid.BreakJointsOnDeath == false)

-- where every part is when nothing moves (root part at ROOT_HEIGHT, feet at 0)
local function partCFrame(name, pose)
	local motorName = nil
	for _, spec in ipairs(Character.PARTS) do
		if spec.name == name then
			motorName = spec.joint
		end
	end
	local part = model:FindFirstChild(name)
	local motor = part:FindFirstChild(motorName)
	local rootJoint = root:FindFirstChild("Root")
	local modelRoot = root.CFrame * rootJoint.C0 * rootJoint.C1:Inverse()
	return modelRoot * motor.C0 * (pose or CFrame.new()) * motor.C1:Inverse(), part
end
local head, headPart = partCFrame("Head")
local body = partCFrame("Body")
local rightArm, armPart = partCFrame("RightArm")
local leftLeg = partCFrame("LeftLeg")
check("head 8x8x8 pixels on top: from 24 to 32 pixels (1.875 blocks tall like Minecraft's model)",
	near(head.Position.Y, 28 * P) and near(headPart.Size.X, 8 * P), tostring(head.Position))
check("body 8x12x4 from 12 to 24 pixels", near(body.Position.Y, 18 * P))
check("right arm 4 wide at the right side (+X), from 12 to 24 pixels (the shoulder at 22)", near(rightArm.Position.X, 6 * P)
	and near(rightArm.Position.Y, 18 * P) and near(armPart.Size.X, 4 * P), tostring(rightArm.Position))
check("left leg at the left side (-X), 1.9 pixels from the middle", near(leftLeg.Position.X, -1.9 * P)
	and near(leftLeg.Position.Y, 6 * P))
local front = headPart:FindFirstChild("SkinFront")
check("skin: the face (front of the head) is at 8,8 in the skin, the hat layer at 40,8",
	front and front:GetAttribute("McSkinFace") == "8,8,8,8"
	and model:FindFirstChild("Hat"):FindFirstChild("SkinFront"):GetAttribute("McSkinFace") == "40,8,8,8")
check("skin: right arm front 44,20 (4x12), left leg front 20,52, body back 32,20",
	armPart:FindFirstChild("SkinFront"):GetAttribute("McSkinFace") == "44,20,4,12"
	and model:FindFirstChild("LeftLeg"):FindFirstChild("SkinFront"):GetAttribute("McSkinFace") == "20,52,4,12"
	and model:FindFirstChild("Body"):FindFirstChild("SkinBack"):GetAttribute("McSkinFace") == "32,20,8,12")
Character.setShape(model, true)
local slimArm, slimPart = partCFrame("RightArm")
check("slim skin: arms 3 pixels wide, still at the shoulder, skin faces 3 wide",
	near(slimPart.Size.X, 3 * P) and near(slimArm.Position.X, 5.5 * P) and model:GetAttribute("McSlim") == true
	and slimPart:FindFirstChild("SkinFront"):GetAttribute("McSkinFace") == "44,20,3,12", tostring(slimArm.Position))
Character.setShape(model, false)

-- the animations
local function sequence(name)
	return roblox.deserializeModel(fs.readFile("../examples/MinecraftWorld/animations/" .. name .. ".rbxm"))[1]
end
local function poseAt(kfs, index, partName)
	local frames = kfs:GetChildren()
	table.sort(frames, function(a, b)
		return a.Time < b.Time
	end)
	for _, pose in ipairs(frames[index]:GetDescendants()) do
		if pose.Name == partName and pose.Weight > 0 then
			return pose.CFrame, frames[index].Time
		end
	end
	return nil
end
local names = {}
for _, name in ipairs(Character.ANIMATIONS) do
	local ok, kfs = pcall(sequence, name)
	if ok and kfs and kfs.ClassName == "KeyframeSequence" then
		table.insert(names, name)
	end
end
check("all 8 animations are there as KeyframeSequences (idle, walk, sneak, sneak_walk, swing, sneak_swing, death, swim)",
	#names == 8, table.concat(names, ","))
local walk = sequence("walk")
local legPose = poseAt(walk, 1, "RightLeg")
local legDown = legPose and (CFrame.new() * legPose):VectorToWorldSpace(Vector3.new(0, -1, 0))
local walkLength = 0
for _, frame in ipairs(walk:GetChildren()) do
	walkLength = math.max(walkLength, frame.Time)
end
check("walk (sprint amount 1): one step cycle 2 pi / 0.6662 ticks = 0.4716 s, looped",
	walk.Loop == true and near(walkLength, 0.4716, 0.001), walkLength)
check("walk start: right leg 1.4 rad back (Minecraft: cos(0) * 1.4), the foot goes to +Z = backwards",
	legDown and near(math.acos(-legDown.Y), 1.4, 0.01) and legDown.Z > 0.9, tostring(legDown))
local armPose = poseAt(walk, 1, "RightArm")
local armDown = armPose and armPose:VectorToWorldSpace(Vector3.new(0, -1, 0))
check("walk start: right arm 1 rad forward (cos(pi) * 1), the hand goes to -Z = forwards",
	armDown and armDown.Z < -0.8, tostring(armDown))
local sneak = sequence("sneak")
local bodyPose = poseAt(sneak, 1, "Body")
local bodyUp = bodyPose and bodyPose:VectorToWorldSpace(Vector3.new(0, 1, 0))
local rootPose = poseAt(sneak, 1, "ModelRoot")
check("sneak: body 0.5 rad forward (top to -Z), 3.2 pixels lower, everything 2 pixels lower",
	bodyUp and bodyUp.Z < -0.45 and near(bodyPose.Position.Y, -3.2 * P) and rootPose and near(rootPose.Position.Y, -2 * P),
	tostring(bodyUp))
local death = sequence("death")
local frames = death:GetChildren()
table.sort(frames, function(a, b)
	return a.Time < b.Time
end)
local lastPose = poseAt(death, #frames, "ModelRoot")
local upAfter = lastPose and lastPose:VectorToWorldSpace(Vector3.new(0, 1, 0))
check("death: falls 90 degrees onto its left side (up -> -X) and lies there until 6 s",
	upAfter and near(upAfter.X, -1, 0.01) and near(frames[#frames].Time, 6), tostring(upAfter))
local swing = sequence("swing")
check("swing: 6 ticks (0.3 s), action priority, not looped", swing.Loop == false
	and swing.Priority == roblox.Enum.AnimationPriority.Action)

-- swimming (Minecraft: setupSwimAnimation + setupRotations)
local swim = sequence("swim")
local swimFrames = swim:GetChildren()
table.sort(swimFrames, function(a, b)
	return a.Time < b.Time
end)
local swimRoot = poseAt(swim, 1, "ModelRoot")
local bodyAxis = swimRoot and swimRoot:VectorToWorldSpace(Vector3.new(0, 1, 0))
local chest = swimRoot and swimRoot:VectorToWorldSpace(Vector3.new(0, 0, -1))
check("swim: the body lies in the water - head forward (up -> -Z), chest down, 1 block back and 0.3 up (about the feet)",
	bodyAxis and near(bodyAxis.Z, -1, 0.01) and chest and near(chest.Y, -1, 0.01)
	and near(swimRoot.Position.Z, 3, 0.01) and near(swimRoot.Position.Y, 0.9, 0.01), tostring(swimRoot))
local strokeArm = poseAt(swim, 1, "RightArm")
local strokeDown = strokeArm and strokeArm:VectorToWorldSpace(Vector3.new(0, -1, 0))
check("swim: 3 arm strokes of 26 ticks in the loop (3.9 s, looped); at the start the arms reach over the head (zRot pi)",
	swim.Loop == true and near(swimFrames[#swimFrames].Time, 3.9, 0.001) and strokeDown and strokeDown.Y > 0.99,
	tostring(strokeDown))
local midStroke = poseAt(swim, 1 + math.floor(#swimFrames * (18 / 78)), "RightArm")
local midDown = midStroke and midStroke:VectorToWorldSpace(Vector3.new(0, -1, 0))
check("swim: in the middle of a stroke (tick 18 of 26) the arm comes round past the side",
	midDown and midDown.Y < 0.5, tostring(midDown))
check("swimming head pitch: -45 degrees (Minecraft: head.xRot -pi/4)", near(Character.SWIM_HEAD_PITCH, -math.pi / 4))

-- riding: Minecraft's riding pose (legs forward + apart, arms a little forward), the body on the seat
do
	local rider = Character.build({ name = "Rider" })
	local rootJoint = rider.HumanoidRootPart:FindFirstChild("Root")
	local hip = rider:FindFirstChild("RightLeg"):FindFirstChild("RightHip")
	local hipBefore = hip.C0
	Character.ride(rider, 2.4)
	check("riding: the body sits 2.4 studs higher (Root joint)", near(rootJoint.C0.Position.Y, -Character.ROOT_HEIGHT + 2.4),
		rootJoint.C0.Position.Y)
	-- the right leg hangs down (-y from the hip): riding, it points forward (-z) and a little to the right (+x)
	local down = (hip.C0 - hip.C0.Position):VectorToWorldSpace(Vector3.new(0, -1, 0))
	check("riding: the right leg points forward and outward (Minecraft: xRot -1.41, yRot 0.31)",
		down.Z < -0.9 and down.X > 0.2 and math.abs(down.Y) < 0.2, down)
	check("riding: the hip stays where it was (only turned)", near((hip.C0.Position - hipBefore.Position).Magnitude, 0))
	Character.ride(rider, nil)
	check("riding: off again - joints back", near(rootJoint.C0.Position.Y, -Character.ROOT_HEIGHT)
		and near((hip.C0.LookVector - hipBefore.LookVector).Magnitude, 0))
end

-- MinecraftSounds: Minecraft's block sound groups + the fallbacks for sounds that are not uploaded
do
	shim.services.ReplicatedStorage = { FindFirstChild = function()
		return nil
	end }
	local Sounds = luau.load(fs.readFile("../examples/MinecraftWorld/MinecraftSounds.luau"), { environment = env })()
	check("sounds: block groups like Minecraft (sandstone = stone, oak_leaves = grass, oak_planks = wood, white_wool = wool)",
		Sounds.groupOf("minecraft:sandstone") == "stone" and Sounds.groupOf("minecraft:oak_leaves") == "grass"
			and Sounds.groupOf("minecraft:oak_planks") == "wood" and Sounds.groupOf("minecraft:white_wool") == "wool"
			and Sounds.groupOf("minecraft:sand") == "sand" and Sounds.groupOf("minecraft:iron_block") == "metal"
			and Sounds.groupOf("minecraft:air") == nil and Sounds.groupOf("minecraft:deepslate") == "stone")
	Sounds.ids["block.grass.step"] = 11
	Sounds.ids["block.stone.step"] = 22
	Sounds.ids["block.stone.break"] = 33
	Sounds.ids["entity.generic.hurt"] = 44
	check("sounds: fallbacks (grass hit -> grass step, wood place -> stone break, zombie hurt -> generic hurt, unknown -> none)",
		Sounds.idFor("block.grass.hit") == 11 and Sounds.idFor("block.wood.place") == 33 and Sounds.idFor("block.wood.fall") == 22
			and Sounds.idFor("entity.zombie.hurt") == 44 and Sounds.idFor("entity.zombie.ambient") == nil
			and Sounds.idFor("ui.button.click") == nil)
end

-- MinecraftSky: Minecraft's light map and clock
shim.services.Lighting = {}
shim.services.Players = { LocalPlayer = nil }
shim.services.RunService = { RenderStepped = nil }
local Sky = luau.load(fs.readFile("../examples/MinecraftWorld/MinecraftSky.luau"), { environment = env })()
check("sky clock: Minecraft's sun angle 0 = noon (12:00), 90 = sunset (18:00), 180 = midnight, 270 = sunrise (6:00)",
	near(Sky.clockTime(0), 12) and near(Sky.clockTime(90), 18) and near(Sky.clockTime(180), 0) and near(Sky.clockTime(270), 6))
check("light map (brightness 50 %): day sky light 1 -> 1.0, night 0.24 -> 0.17, nothing -> 0",
	near(Sky.brightness(1), 1) and near(Sky.brightness(0.24), 0.172, 0.005) and near(Sky.brightness(0), 0),
	Sky.brightness(0.24))

print(string.format("\n%d ok, %d failed", results.ok, results.fail))
process.exit(if results.fail > 0 then 1 else 0)
