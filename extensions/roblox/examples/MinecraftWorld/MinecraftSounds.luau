--!strict
--[[
	MinecraftSounds - Minecraft's sounds in Roblox (ModuleScript "MinecraftSounds" in ReplicatedStorage, clients only)

	Roblox can only play uploaded sounds: MinecraftSoundIds (event -> asset id) says which ones there are -
	tools/upload_sounds.py uploads them once and writes that file (any other asset ids work too, e.g. sounds from the
	Creator Store). A sound without an id falls back to its family (block.grass.hit -> block.grass.step ->
	block.stone.step, entity.zombie.hurt -> entity.generic.hurt) - and stays silent if there is none.

	    Sounds.play("block.stone.break", position, volume, pitch)   -- like Minecraft: heard up to 16 blocks x volume
	    Sounds.stepSound("minecraft:oak_planks")                     -- "block.wood.step" (Minecraft's block sound group)
]]
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Sounds = {}

local ids: { [string]: number } = {}
do
	local module = ReplicatedStorage:FindFirstChild("MinecraftSoundIds")
	if module and module:IsA("ModuleScript") then
		local ok, loaded = pcall(require, module)
		if ok and type(loaded) == "table" then
			ids = loaded :: any
		end
	end
end
Sounds.ids = ids

local STUDS_PER_BLOCK = 3
local MAX_PLAYING = 24 -- at the same time (Minecraft: 247 channels - Roblox does not need that many)
local GAIN = 0.8 -- Minecraft's volume 1 = this Roblox volume

--- Is any sound uploaded at all? (Without: nothing to do - footsteps are not even counted.)
function Sounds.available(): boolean
	return next(ids) ~= nil
end

--[[
	Minecraft's block sound groups (SoundType) by the block's name - the usual ones, in this order (sandstone is stone,
	oak_leaves are grass, not wood). Everything else sounds like stone.
]]
local GROUPS: { { string } } = {
	{ "sandstone", "stone" }, { "soul_s", "soul_sand" }, { "sand", "sand" }, { "gravel", "gravel" }, { "clay", "gravel" },
	{ "glass", "glass" }, { "ice", "glass" }, { "wool", "wool" }, { "carpet", "wool" }, { "snow", "snow" },
	{ "ladder", "ladder" }, { "leaves", "grass" }, { "grass", "grass" }, { "dirt", "gravel" }, { "podzol", "grass" },
	{ "mycelium", "grass" }, { "farmland", "gravel" }, { "moss", "moss" }, { "hay", "grass" }, { "sapling", "grass" },
	{ "fern", "grass" }, { "flower", "grass" }, { "vine", "grass" }, { "kelp", "grass" }, { "bush", "grass" },
	{ "log", "wood" }, { "planks", "wood" }, { "wood", "wood" }, { "chest", "wood" }, { "barrel", "wood" },
	{ "bookshelf", "wood" }, { "crafting", "wood" }, { "oak", "wood" }, { "spruce", "wood" }, { "birch", "wood" },
	{ "jungle", "wood" }, { "acacia", "wood" }, { "mangrove", "wood" }, { "cherry", "wood" }, { "bamboo", "wood" },
	{ "crimson", "wood" }, { "warped", "wood" }, { "note_block", "wood" }, { "iron", "metal" }, { "gold", "metal" },
	{ "copper", "metal" }, { "anvil", "metal" }, { "netherite", "metal" }, { "chain", "metal" }, { "lantern", "metal" },
	{ "hopper", "metal" }, { "cauldron", "metal" }, { "rail", "metal" },
}
local groupCache: { [string]: string } = {}

--- Minecraft's sound group of a block ("stone", "wood", "grass" ...) - nil for air / fluids.
function Sounds.groupOf(blockName: string): string?
	local cached = groupCache[blockName]
	if cached then
		return if cached == "" then nil else cached
	end
	local stripped = string.gsub(blockName, "^minecraft:", "")
	local name = string.lower(stripped)
	name = string.match(name, "^[^%[]+") or name
	local group = "stone"
	if name == "air" or name == "cave_air" or name == "void_air" or name == "water" or name == "lava" or name == "" then
		group = ""
	else
		for _, entry in ipairs(GROUPS) do
			if string.find(name, entry[1], 1, true) then
				group = entry[2]
				break
			end
		end
	end
	groupCache[blockName] = group
	return if group == "" then nil else group
end

function Sounds.stepSound(blockName: string): string?
	local group = Sounds.groupOf(blockName)
	return if group then "block." .. group .. ".step" else nil
end

--- The asset id for a Minecraft sound event - its own, or the nearest of its family.
function Sounds.idFor(event: string): number?
	local id = ids[event]
	if id then
		return id
	end
	local group, action = string.match(event, "^block%.([%w_]+)%.(%w+)$")
	if group and action then
		local similar = if action == "hit" or action == "fall" then "step" elseif action == "place" then "break" else nil
		return (similar and ids["block." .. group .. "." .. similar]) or ids["block.stone." .. action]
			or (similar and ids["block.stone." .. similar]) or nil
	end
	local kind = string.match(event, "^entity%.[%w_]+%.(%w+)$")
	if kind == "hurt" or kind == "death" then
		return ids["entity.generic." .. kind] or ids["entity.player.hurt"]
	end
	return nil
end

local playing = 0

--- Plays a Minecraft sound at a place (studs): linear fall-off over 16 blocks x volume, pitch = speed (Minecraft).
function Sounds.play(event: string, position: Vector3, volume: number?, pitch: number?)
	local id = Sounds.idFor(event)
	if not id or id <= 0 or playing >= MAX_PLAYING then
		return
	end
	local loudness = math.clamp(tonumber(volume) or 1, 0, 16)
	local attachment = Instance.new("Attachment")
	attachment.Name = "McSound"
	attachment.WorldPosition = position
	local sound = Instance.new("Sound")
	sound.SoundId = "rbxassetid://" .. tostring(id)
	sound.Volume = math.min(loudness, 1) * GAIN
	sound.PlaybackSpeed = math.clamp(tonumber(pitch) or 1, 0.5, 2)
	sound.RollOffMode = Enum.RollOffMode.Linear
	sound.RollOffMinDistance = 0.5
	sound.RollOffMaxDistance = 16 * math.max(1, loudness) * STUDS_PER_BLOCK
	sound.Parent = attachment
	attachment.Parent = workspace.Terrain
	playing += 1
	local done = false
	local function finish()
		if not done then
			done = true
			playing -= 1
			attachment:Destroy()
		end
	end
	sound.Ended:Connect(finish)
	task.delay(10, finish) -- (never played / never ended: gone anyway)
	sound:Play()
end

--- A sound without a place (his level-up, a button click in a menu): plain, at full volume.
function Sounds.playHere(event: string, volume: number?, pitch: number?)
	local camera = workspace.CurrentCamera
	if camera then
		Sounds.play(event, camera.CFrame.Position, volume, pitch)
	end
end

return Sounds
