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
check("hitbox 0.6 x 1.8 blocks: the root part IS the hitbox from the feet up (hip height 0, stands on edges like MC)",
	near(root.Size.X, 1.8) and near(root.Size.Y, 5.4) and humanoid.HipHeight == 0 and near(root.CFrame.Position.Y, 2.7),
	tostring(root.Size))
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
check("all 7 animations are there as KeyframeSequences (idle, walk, sneak, sneak_walk, swing, sneak_swing, death)",
	#names == 7, table.concat(names, ","))
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

print(string.format("\n%d ok, %d failed", results.ok, results.fail))
process.exit(if results.fail > 0 then 1 else 0)
