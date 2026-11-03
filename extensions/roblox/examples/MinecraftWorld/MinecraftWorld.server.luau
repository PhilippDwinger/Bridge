--[[
	MinecraftWorld - the Minecraft world in Roblox (Script in ServerScriptService)

	The Minecraft server (mod BridgeGameSync) is a Bridge client too. This game server:
	  1. asks it for the world (command mcworld.info + mcworld.chunks) and builds every block as a grey placeholder
	     cube - neighbouring blocks are merged into bigger parts (greedy meshing), so a flat map is only a few parts
	  2. follows every change (topic mcworld.changes): placed / broken blocks, whole chunks after big changes, a full
	     reload after a Minecraft restart or a lost connection
	  3. players: the script PlayerSync (same game) shows the Minecraft players (as Minecraft characters) and sends ours to
	     Minecraft (shown there as mannequins). Same coordinates: 1 block = 3 studs, the lowest Minecraft layer at y 0.
	  4. textures + items (command mcworld.assets): pictures from the Minecraft game itself - textured blocks get their
	     own parts with a Texture per side, models (levers, redstone, stairs ...) parts per box; the client script
	     MinecraftClient turns the pixels into images (EditableImage, they only exist on the client) and shows
	     hotbar + inventory
	  5. every Roblox player is a Minecraft player there (game mode + inventory in Minecraft, command mcworld.player):
	     building (RemoteEvent Edit -> command mcworld.edit) goes through Minecraft's own code - right click "use"
	     (doors, levers, buttons, or placing: logs lie the way you click, pistons face you), left click "break"
	     (survival: after the breaking time, the drops lie there for whoever is first); the inventory (Inventory: clicks,
	     crafting, creative items); block looks for every state ("minecraft:oak_log[axis=x]": cubes and models)
	  6. health like Minecraft (20 = 10 hearts, not in creative / spectator): fall damage (Fall), hitting a Minecraft
	     player's NPC (Attack -> command mcworld.hurt), Minecraft players hitting our mannequins (direct message
	     "mc.hurt"); dying = Minecraft's death (message, the inventory falls out)
	  7. everybody is a Minecraft player: StarterCharacter = MinecraftCharacter (Minecraft's model, hitbox, speeds,
	     jump; Workspace.Gravity like Minecraft). Skins (command mcworld.skin): every model with the attribute
	     McSkinUser gets McSkin (key of the picture) + slim / wide arms; the client asks GetSkin for the pixels.
	     Roblox players wear a Minecraft default skin (fixed by their user id) or "/skin <Minecraft name>".
	  8. chat both ways (RemoteEvent Chat): Roblox messages -> command mcworld.chat, "/..." -> command mcworld.command
	     (the Minecraft command runs as the player's mannequin, the answer comes back into his chat), Minecraft's chat
	     (topic mcworld.chat) -> everybody's chat
	  9. items lying around (topic mcworld.items): an invisible part per item in workspace.MinecraftItems (attributes
	     McItem, McCount), the clients draw it like Minecraft; picked up in Minecraft by whoever is first

	Needs in ServerStorage: Bridge, MinecraftWorldConfig, MinecraftWorldClient (shared Bridge client), PlayerSyncConfig.
]]
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")
local StarterPlayer = game:GetService("StarterPlayer")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))
local client = require(ServerStorage:WaitForChild("MinecraftWorldClient"))
-- (missing = Rojo still serves an older project: restart "rojo serve" and connect the plugin again)
local characterModule = ReplicatedStorage:WaitForChild("MinecraftCharacter", 15)
if not characterModule then
	error("[MinecraftWorld] ReplicatedStorage.MinecraftCharacter fehlt - Rojo neu starten: "
		.. "rojo serve minecraft-world.project.json --port 34874, dann im Rojo-Plugin neu verbinden")
end
local Character = require(characterModule :: any)

local INFO = Config.WorldPrefix .. ".info"
local CHUNKS = Config.WorldPrefix .. ".chunks"
local CHANGES = Config.WorldPrefix .. ".changes"
local ASSETS = Config.WorldPrefix .. ".assets"
local EDIT = Config.WorldPrefix .. ".edit"
local HURT = Config.WorldPrefix .. ".hurt"
local SKIN = Config.WorldPrefix .. ".skin"
local CHAT = Config.WorldPrefix .. ".chat"
local COMMAND = Config.WorldPrefix .. ".command"
local PLAYER = Config.WorldPrefix .. ".player"
local ITEMS = Config.WorldPrefix .. ".items"
local CHAT_PER_5S = 6 -- messages / commands per player in 5 seconds
local MAX_CHAT = 256 -- characters, like Minecraft
local MAX_HEALTH = 20 -- Minecraft: 10 hearts
local ATTACK_REACH = 5 -- blocks (Minecraft creative 5, survival 3) + a little slack below
local ATTACKS_PER_SECOND = 4
local CHUNKS_PER_CALL = Config.ChunksPerCall or 4
local WAIT_FOR_WORLD = 15 -- seconds; after that players spawn on a waiting platform until the world is there
local REACH = 7 -- blocks from the character to a block it changes (Minecraft creative: 5 from the eyes, + slack)
local EDITS_PER_SECOND = 12 -- per player
local AIR = { ["minecraft:air"] = true, ["minecraft:cave_air"] = true, ["minecraft:void_air"] = true }
-- Without pictures from Minecraft (old mod / dedicated server) the items are still there, with a plain icon
local DEFAULT_ITEMS = { { id = "minecraft:grass_block", name = "Grass Block", max = 64 } }
-- Roblox face -> Minecraft face (same axes: Roblox Front = -Z = Minecraft north, Right = +X = east)
local FACES = {
	{ Enum.NormalId.Top, "up" },
	{ Enum.NormalId.Bottom, "down" },
	{ Enum.NormalId.Front, "north" },
	{ Enum.NormalId.Back, "south" },
	{ Enum.NormalId.Right, "east" },
	{ Enum.NormalId.Left, "west" },
}
local MAX_ASK = 64 -- unknown blocks per assets call

-- Characters only come when there is ground to stand on
Players.CharacterAutoLoads = false

-- Everybody looks and moves like a Minecraft player (the rig, its measurements and speeds: MinecraftCharacter)
workspace.Gravity = Character.GRAVITY
pcall(function()
	StarterPlayer.LoadCharacterAppearance = false -- no Roblox clothes / hats on the Minecraft body
end)
if not StarterPlayer:FindFirstChild("StarterCharacter") then
	local template = Character.build({ name = "StarterCharacter" })
	template.Parent = StarterPlayer
end
do
	-- no Roblox "Animate" script in the characters (it would play Roblox animations): the client plays Minecraft's
	local scripts = StarterPlayer:FindFirstChild("StarterCharacterScripts")
	if scripts and not scripts:FindFirstChild("Animate") then
		local empty = Instance.new("LocalScript")
		empty.Name = "Animate"
		empty.Parent = scripts
	end
end

local worldFolder = workspace:FindFirstChild("MinecraftWorld") or Instance.new("Folder")
worldFolder.Name = "MinecraftWorld"
worldFolder.Parent = workspace

local world = {
	info = nil, -- answer of mcworld.info
	chunks = {}, -- "x,z" -> {x, z, sections = {[sectionY] = {palette, cells, parts}}, folder}
	generation = 0, -- counts up with every (re)load; an old load stops when it sees a newer one
	loaded = false,
	-- pictures + items from Minecraft: {available, textures = {key -> {w, h, pixels: buffer}}, blocks, items, gui,
	-- other = {name -> true} for blocks Minecraft has no cube pictures for (they stay grey), asked = {name -> true}}
	assets = nil,
}

-- Remotes for the client script (pictures, building)
local remotes = ReplicatedStorage:FindFirstChild("MinecraftWorld") or Instance.new("Folder")
remotes.Name = "MinecraftWorld"
remotes.Parent = ReplicatedStorage
local function remote(className, name)
	local item = remotes:FindFirstChild(name) or Instance.new(className)
	item.Name = name
	item.Parent = remotes
	return item
end
local getAssets = remote("RemoteFunction", "GetAssets") -- client asks: pictures, items, scale
local assetsChanged = remote("RemoteEvent", "AssetsChanged") -- server tells: new pictures (after a Minecraft reload)
local editRemote = remote("RemoteEvent", "Edit") -- client wants: (action "use" | "break", x, y, z, info)
local moveRemote = remote("RemoteEvent", "Move") -- client says: (sneaking, sprinting) - shown to everybody + Minecraft
local attackRemote = remote("RemoteEvent", "Attack") -- client: (NPC model) hits a Minecraft player
local fallRemote = remote("RemoteEvent", "Fall") -- client: (blocks fallen) - Minecraft's fall damage
local hurtRemote = remote("RemoteEvent", "Hurt") -- server -> client: (amount, from position or nil) red flash, knockback
local getSkin = remote("RemoteFunction", "GetSkin") -- client asks: (skin key) -> {w, h, pixels} (64 x 64)
local chatRemote = remote("RemoteEvent", "Chat")
local swingRemote = remote("RemoteEvent", "Swing") -- client: hit into the air (the arm swings, Minecraft sees it)
-- client: (op, ...) "click" | "close" | "creative" | "pick" | "drop" | "state"; server -> client: ("state", state)
local inventoryRemote = remote("RemoteEvent", "Inventory")
local miningSpeed = remote("RemoteFunction", "MiningSpeed") -- client asks: (x, y, z, slot, ground) -> progress per tick

local function log(...)
	print("[MinecraftWorld]", ...)
end

local function chunkKey(x, z)
	return x .. "," .. z
end

-- region blocks -> parts
-- One place that decides how a Minecraft block looks. Block names carry what their look depends on
-- ("minecraft:oak_log[axis=x]", "minecraft:lever[face=wall,facing=east,powered=true]"); Minecraft sends the look of
-- each such state (MinecraftWorld mod, Models): a cube (6 pictures, already turned the right way) or a model (boxes,
-- also turned ones, with their pictures + what you bump into + what you aim at). Without a look: the grey cube.
local function baseName(name)
	return string.match(name, "^([^%[]+)") or name
end

local function renderKey(name)
	if name == nil or AIR[name] or AIR[baseName(name)] then
		return nil
	end
	local assets = world.assets
	if assets and assets.blocks[name] then
		return name
	end
	return "placeholder"
end

-- A cube block is merged with its neighbours of the same kind (greedy meshing); models, and cubes with a collision
-- of their own (soul sand), stand alone
local function standsAlone(key)
	local look = world.assets and world.assets.blocks[key]
	return look ~= nil and (look.cube ~= true or look.single == true)
end

local NORMALS = { up = Enum.NormalId.Top, down = Enum.NormalId.Bottom, north = Enum.NormalId.Front,
	south = Enum.NormalId.Back, east = Enum.NormalId.Right, west = Enum.NormalId.Left }
local THIN = 0.02 -- studs: the thickness of flat pieces (redstone dust lies 0.05 studs above the block)

-- The size of a face on the part: width (U) and height (V) of its picture
local function faceSize(part, normal)
	local size = part.Size
	if normal == Enum.NormalId.Top or normal == Enum.NormalId.Bottom then
		return size.X, size.Z
	elseif normal == Enum.NormalId.Left or normal == Enum.NormalId.Right then
		return size.Z, size.Y
	end
	return size.X, size.Y
end

local function pictureOn(part, normal, key, tileU, tileV)
	local texture = Instance.new("Texture")
	texture.Name = "McTexture"
	texture.Face = normal
	texture.StudsPerTileU = tileU
	texture.StudsPerTileV = tileV
	texture:SetAttribute("McTexture", key)
	texture.Parent = part
end

local function plainPart(name)
	local part = Instance.new("Part")
	part.Name = name
	part.Anchored = true
	part.CanCollide = false
	part.CanQuery = false
	part.CanTouch = false
	part.Transparency = 1
	part.CastShadow = false
	part.Material = Enum.Material.SmoothPlastic
	part.TopSurface = Enum.SurfaceType.Smooth
	part.BottomSurface = Enum.SurfaceType.Smooth
	return part
end

-- boxes in pixels of the block (0..16) -> invisible parts: collision ("Collision") or aim ("Outline"). Collision
-- parts can always be found by raycasts (standing on a fence); McSolidOnly = not for aiming (the client looks past)
local function boxParts(parent, boxes, corner, unit, name, collide, query, solidOnly)
	for _, box in ipairs(boxes or {}) do
		local size = Vector3.new(box[4] - box[1], box[5] - box[2], box[6] - box[3]) * unit
		if size.X > 0.001 and size.Y > 0.001 and size.Z > 0.001 then
			local part = plainPart(name)
			part.Size = Vector3.new(math.max(size.X, THIN), math.max(size.Y, THIN), math.max(size.Z, THIN))
			part.CFrame = CFrame.new(corner + Vector3.new(box[1] + box[4], box[2] + box[5], box[3] + box[6]) / 2 * unit)
			part.CanCollide = collide
			part.CanQuery = query
			if solidOnly then
				part:SetAttribute("McSolidOnly", true)
			end
			part.Parent = parent
		end
	end
end

--[[
	A block with a model (lever, piston head, redstone, stairs, trapdoor, ...): a Model with
	- one invisible part per box of the look, its faces showing their pictures (a turned box = a turned part)
	- "Collision" parts (what you bump into - none for redstone, levers, buttons)
	- "Outline" parts (what you aim at; the client outlines them like Minecraft)
]]
local function buildModel(key, look, corner, scale, cell)
	local model = Instance.new("Model")
	model.Name = key
	model:SetAttribute("McBlock", cell) -- which block it is (a piston arm reaches into the next one)
	local unit = scale / 16
	for _, piece in ipairs(look.parts or {}) do
		local part = plainPart("Piece")
		if type(piece.b) == "table" then
			local b = piece.b
			local size = Vector3.new(b[4] - b[1], b[5] - b[2], b[6] - b[3]) * unit
			part.Size = Vector3.new(math.max(size.X, THIN), math.max(size.Y, THIN), math.max(size.Z, THIN))
			part.CFrame = CFrame.new(corner + Vector3.new(b[1] + b[4], b[2] + b[5], b[3] + b[6]) / 2 * unit)
		elseif type(piece.c) == "table" and type(piece.s) == "table" and type(piece.r) == "table" then
			local c, size, r = piece.c, piece.s, piece.r
			part.Size = Vector3.new(math.max(size[1] * unit, THIN), math.max(size[2] * unit, THIN), math.max(size[3] * unit, THIN))
			part.CFrame = CFrame.new(corner + Vector3.new(c[1], c[2], c[3]) * unit)
				* CFrame.new(0, 0, 0, r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9])
		else
			continue
		end
		for direction, picture in pairs(piece.f or {}) do
			local normal = NORMALS[direction]
			if normal then
				local u, v = faceSize(part, normal)
				pictureOn(part, normal, picture, u, v)
			end
		end
		part.Parent = model
	end
	-- what you bump into + what you aim at (the same boxes: one part does both)
	local collision, outline = look.boxes or {}, look.outline or look.boxes or {}
	local same = #collision == #outline
	if same then
		for i, box in ipairs(collision) do
			for j = 1, 6 do
				if box[j] ~= outline[i][j] then
					same = false
				end
			end
		end
	end
	if same then
		boxParts(model, collision, corner, unit, "Collision", true, true)
	else
		boxParts(model, collision, corner, unit, "Collision", true, true, true)
		boxParts(model, outline, corner, unit, "Outline", false, true)
	end
	return model
end

local function cellIndex(x, y, z) -- 1-based, order y, z, x (as the mod sends it)
	return y * 256 + z * 16 + x + 1
end

--- Greedy meshing of one 16x16x16 section: boxes {x, y, z, w, h, d} of blocks with the same look.
local function meshSection(section)
	local keys = table.create(4096)
	for i = 1, 4096 do
		keys[i] = renderKey(section.palette[section.cells[i] + 1])
	end
	local done = {}
	local boxes = {}
	for y = 0, 15 do
		for z = 0, 15 do
			for x = 0, 15 do
				local start = cellIndex(x, y, z)
				local key = keys[start]
				if key and not done[start] then
					local single = standsAlone(key) -- a model (lever, stairs, ...) or a cube with its own collision: never merged
					local function same(cx, cy, cz)
						local i = cellIndex(cx, cy, cz)
						return not single and keys[i] == key and not done[i]
					end
					local w = 1
					while x + w < 16 and same(x + w, y, z) do
						w += 1
					end
					local d = 1
					while z + d < 16 do
						local rowOk = true
						for dx = 0, w - 1 do
							if not same(x + dx, y, z + d) then
								rowOk = false
								break
							end
						end
						if not rowOk then
							break
						end
						d += 1
					end
					local h = 1
					while y + h < 16 do
						local layerOk = true
						for dz = 0, d - 1 do
							for dx = 0, w - 1 do
								if not same(x + dx, y + h, z + dz) then
									layerOk = false
									break
								end
							end
							if not layerOk then
								break
							end
						end
						if not layerOk then
							break
						end
						h += 1
					end
					for dy = 0, h - 1 do
						for dz = 0, d - 1 do
							for dx = 0, w - 1 do
								done[cellIndex(x + dx, y + dy, z + dz)] = true
							end
						end
					end
					table.insert(boxes, { x = x, y = y, z = z, w = w, h = h, d = d, key = key })
				end
			end
		end
	end
	return boxes
end

--[[
	Builds the parts of a section - only what changed: a part whose box (block kind, place, size) is still the same stays
	as it is, new parts are made BEFORE old ones go. So the ground under a player is never gone for a moment (no jolt
	of the camera), and the textures of unchanged blocks are not touched at all. force = make every part new (after new
	pictures from Minecraft: the look of a block kind may have changed).
]]
local function boxId(box)
	return string.format("%s|%d|%d|%d|%d|%d|%d", box.key, box.x, box.y, box.z, box.w, box.h, box.d)
end

local function renderSection(chunk, sectionY, section, force)
	local old = section.parts
	local kept = {}
	local scale = world.info.studsPerBlock
	local minY = world.info.minY
	for _, box in ipairs(meshSection(section)) do
		local id = boxId(box)
		local existing = if force then nil else old[id]
		if existing and existing.Parent then
			old[id] = nil
			kept[id] = existing
			continue
		end
		local blockX = chunk.x * 16 + box.x
		local blockY = sectionY * 16 + box.y
		local blockZ = chunk.z * 16 + box.z
		local look = world.assets and world.assets.blocks[box.key]
		local corner = Vector3.new(blockX * scale, (blockY - minY) * scale, blockZ * scale)
		if look and look.cube ~= true then
			local model = buildModel(box.key, look, corner, scale, Vector3.new(blockX, blockY, blockZ))
			model.Parent = chunk.folder
			kept[id] = model
			continue
		end
		local part = Instance.new("Part")
		part.Name = "Blocks"
		part.Anchored = true
		part.CanCollide = true
		part.Material = Config.BlockMaterial or Enum.Material.SmoothPlastic
		part.Color = Config.BlockColor or Color3.fromRGB(163, 162, 165)
		part.TopSurface = Enum.SurfaceType.Smooth
		part.BottomSurface = Enum.SurfaceType.Smooth
		part.Size = Vector3.new(box.w * scale, box.h * scale, box.d * scale)
		part.CFrame = CFrame.new(
			(blockX + box.w / 2) * scale,
			(blockY - minY + box.h / 2) * scale,
			(blockZ + box.d / 2) * scale
		)
		if look then
			-- Textured cube: the colour shows until the client has made the pictures; one tile = one block.
			-- Glass / leaves: the part is invisible, only the pictures (with their holes) show.
			part.Name = box.key
			part.Color = Color3.fromRGB(look.color[1], look.color[2], look.color[3])
			if look.transparent then
				part.Transparency = 1
				part.CastShadow = false
			end
			if look.fluid then
				-- water / lava: see-through, you go through it, nobody aims at it
				part.CanCollide = false
				part.CanQuery = false
				part.CanTouch = false
			end
			for _, face in ipairs(FACES) do
				pictureOn(part, face[1], look.faces[face[2]], scale, scale)
			end
			if look.boxes then
				-- a cube with its own collision (soul sand): the picture does not collide, its boxes do
				part.CanCollide = false
				part.CanQuery = look.outline == nil
				local holder = Instance.new("Model")
				holder.Name = box.key
				part.Parent = holder
				boxParts(holder, look.boxes, corner, scale / 16, "Collision", true, true, look.outline ~= nil)
				if look.outline then
					boxParts(holder, look.outline, corner, scale / 16, "Outline", false, true)
				end
				holder.Parent = chunk.folder
				kept[id] = holder
				continue
			end
		end
		part.Parent = chunk.folder
		kept[id] = part
	end
	for _, part in pairs(old) do
		part:Destroy() -- (only now: the new parts are already there)
	end
	section.parts = kept
end

local function decodeSection(data)
	local cells = table.create(4096)
	local count = 0
	local runs = data.runs or {}
	for i = 1, #runs - 1, 2 do
		local index, length = runs[i], runs[i + 1]
		for _ = 1, length do
			count += 1
			cells[count] = index
		end
	end
	if count ~= 4096 then
		error("section y=" .. tostring(data.y) .. " has " .. count .. " blocks instead of 4096")
	end
	return { palette = data.palette or { "minecraft:air" }, cells = cells, parts = {} }
end

local function renderAll(force)
	for _, chunk in pairs(world.chunks) do
		for sectionY, section in pairs(chunk.sections) do
			renderSection(chunk, sectionY, section, force)
		end
	end
end

-- Blocks (states) Minecraft has not sent the look of yet (they appear in the world) and items it has not described yet
-- (they come into an inventory): ask for them in one call, then build again
local askQueue = { blocks = {}, items = {} }
local askScheduled = false
local mergeBlocks -- below (adds an assets answer)
local afterNewPictures -- below (re-render + tell the clients)
local loadItemIcons -- below
local noticeItems -- below

local function askLater()
	local assets = world.assets
	if askScheduled or (#askQueue.blocks == 0 and #askQueue.items == 0) then
		return
	end
	askScheduled = true
	task.delay(0.3, function()
		askScheduled = false
		local blocks, items = {}, {}
		while #askQueue.blocks > 0 and #blocks < MAX_ASK do
			table.insert(blocks, table.remove(askQueue.blocks, 1))
		end
		while #askQueue.items > 0 and #items < MAX_ASK do
			table.insert(items, table.remove(askQueue.items, 1))
		end
		local ok, result = pcall(client.Call, client, ASSETS, { blocks = blocks, items = items }, { Timeout = 20 })
		if world.assets ~= assets then
			return -- everything was loaded again meanwhile
		end
		if ok and type(result) == "table" then
			mergeBlocks(assets, result)
			for _, name in ipairs(blocks) do
				if not assets.blocks[name] then
					assets.other[name] = true
				end
			end
			afterNewPictures()
		else
			for _, name in ipairs(blocks) do
				assets.asked[name] = nil -- try again when it shows up next time
			end
			for _, id in ipairs(items) do
				assets.asked["item " .. id] = nil
			end
		end
		askLater()
	end)
end

local function noticeBlocks(names)
	local assets = world.assets
	if not assets or not assets.available then
		return
	end
	for _, name in ipairs(names) do
		if type(name) == "string" and not AIR[baseName(name)] and not assets.blocks[name] and not assets.other[name]
			and not assets.asked[name] then
			assets.asked[name] = true
			table.insert(askQueue.blocks, name)
		end
	end
	askLater()
end

function noticeItems(ids)
	local assets = world.assets
	if not assets then
		return
	end
	for _, id in ipairs(ids) do
		if type(id) == "string" and not assets.itemsById[id] and not assets.asked["item " .. id] then
			assets.asked["item " .. id] = true
			table.insert(askQueue.items, id)
		end
	end
	askLater()
end

local function applyChunk(data)
	local key = chunkKey(data.x, data.z)
	local old = world.chunks[key]
	-- a chunk loaded again (after /fill, ...): its parts that are still right stay, only the changes are rebuilt
	local folder = if old then old.folder else Instance.new("Folder")
	folder.Name = "Chunk " .. key
	local chunk = { x = data.x, z = data.z, sections = {}, folder = folder }
	for _, sectionData in ipairs(data.sections or {}) do
		local section = decodeSection(sectionData)
		local before = old and old.sections[sectionData.y]
		if before then
			section.parts = before.parts
			old.sections[sectionData.y] = nil
		end
		noticeBlocks(section.palette)
		chunk.sections[sectionData.y] = section
		renderSection(chunk, sectionData.y, section)
	end
	if old then
		for _, gone in pairs(old.sections) do -- sections that are only air now
			for _, part in pairs(gone.parts) do
				part:Destroy()
			end
		end
	end
	folder.Parent = worldFolder
	world.chunks[key] = chunk
end
-- endregion

-- region spawn + characters
local spawnLocation = nil
local waitingPlatform = nil
local charactersEnabled = false

local function spawnPosition()
	local info = world.info
	local scale = info.studsPerBlock
	return Vector3.new((info.spawn[1] + 0.5) * scale, (info.spawn[2] - info.minY) * scale + 0.5, (info.spawn[3] + 0.5) * scale)
end

local function setSpawn(position)
	if not spawnLocation then
		-- Roblox picks a random spawn if there are several (the Baseplate template has one at 0,0,0): only ours
		for _, item in ipairs(workspace:GetDescendants()) do
			if item:IsA("SpawnLocation") then
				item.Enabled = false
			end
		end
		spawnLocation = Instance.new("SpawnLocation")
		spawnLocation.Name = "MinecraftSpawn"
		spawnLocation.Anchored = true
		spawnLocation.CanCollide = false
		spawnLocation.Transparency = 1
		spawnLocation.Size = Vector3.new(4, 1, 4)
		spawnLocation.Neutral = true
		spawnLocation.Duration = 0
		spawnLocation.Parent = workspace
	end
	spawnLocation.CFrame = CFrame.new(position)
end

local function enableCharacters()
	if charactersEnabled then
		return
	end
	charactersEnabled = true
	Players.CharacterAutoLoads = true
	for _, player in ipairs(Players:GetPlayers()) do
		if not player.Character then
			task.spawn(function()
				pcall(player.LoadCharacter, player)
			end)
		end
	end
end

Players.PlayerAdded:Connect(function(player)
	if charactersEnabled and not player.Character then
		pcall(player.LoadCharacter, player)
	end
end)

-- No world after a while (Minecraft server not running?): wait on a platform high up instead of not spawning at all
task.delay(WAIT_FOR_WORLD, function()
	if world.loaded then
		return
	end
	log("no Minecraft world yet - players wait on a platform")
	waitingPlatform = Instance.new("Part")
	waitingPlatform.Name = "WaitingForMinecraft"
	waitingPlatform.Anchored = true
	waitingPlatform.Size = Vector3.new(24, 1, 24)
	waitingPlatform.CFrame = CFrame.new(0, 1500, 0)
	waitingPlatform.Parent = workspace
	setSpawn(Vector3.new(0, 1501, 0))
	enableCharacters()
end)

local function onWorldReady()
	local position = spawnPosition()
	setSpawn(position)
	if waitingPlatform then
		-- Everybody who waited goes down to the Minecraft spawn
		for _, player in ipairs(Players:GetPlayers()) do
			local character = player.Character
			if character and character.PrimaryPart and character.PrimaryPart.Position.Y > 1000 then
				character:PivotTo(CFrame.new(position + Vector3.new(0, 4, 0)))
			end
		end
		waitingPlatform:Destroy()
		waitingPlatform = nil
	end
	enableCharacters()
end
-- endregion

-- region pictures + items from Minecraft
local function clientAssets()
	local assets, info = world.assets, world.info
	if not assets or not info then
		return nil
	end
	return {
		available = assets.available,
		reason = assets.reason,
		scale = info.studsPerBlock,
		minY = info.minY,
		maxY = info.maxY,
		textures = assets.textures,
		blocks = assets.blocks,
		items = assets.items,
		itemsById = assets.itemsById,
		gui = assets.gui,
	}
end

getAssets.OnServerInvoke = function()
	return clientAssets()
end

local function decodeTexture(texture)
	if type(texture) ~= "table" or type(texture.rgba) ~= "string" or type(texture.w) ~= "number"
		or type(texture.h) ~= "number" then
		return nil
	end
	local ok, raw = pcall(function()
		return Bridge.Inflate(Bridge.Base64Decode(texture.rgba))
	end)
	if not ok or #raw ~= texture.w * texture.h * 4 then
		return nil
	end
	return { w = texture.w, h = texture.h, pixels = buffer.fromstring(raw) }
end

-- Adds textures + blocks + items of an assets answer. Blocks whose pictures did not all arrive count as "other" (grey).
local function lookComplete(assets, look)
	if type(look) ~= "table" then
		return false
	end
	if look.cube == true then
		if type(look.faces) ~= "table" then
			return false
		end
		for _, face in ipairs(FACES) do
			if not assets.textures[look.faces[face[2]]] then
				return false
			end
		end
		return true
	end
	if look.model ~= true or type(look.parts) ~= "table" then
		return false
	end
	for _, piece in ipairs(look.parts) do
		for _, picture in pairs(type(piece) == "table" and piece.f or {}) do
			if not assets.textures[picture] then
				return false
			end
		end
	end
	return true
end

function mergeBlocks(assets, result)
	for key, texture in pairs(result.textures or {}) do
		assets.textures[key] = decodeTexture(texture)
	end
	for name, look in pairs(result.blocks or {}) do
		if lookComplete(assets, look) then
			assets.blocks[name] = look
			assets.other[name] = nil
		else
			assets.other[name] = true
		end
	end
	for _, item in ipairs(if type(result.items) == "table" then result.items else {}) do
		if type(item) == "table" and type(item.id) == "string" then
			assets.itemsById[item.id] = item
		end
	end
end

local function count(map)
	local n = 0
	for _ in pairs(map) do
		n += 1
	end
	return n
end

local function loadAssets(generation)
	-- the GUI + the item list first (small: the world can be built right away); the item icons come afterwards
	local ok, result = pcall(client.Call, client, ASSETS, { gui = true }, { Timeout = 30 })
	if generation ~= world.generation then
		return
	end
	local assets = { available = false, textures = {}, blocks = {}, items = DEFAULT_ITEMS, itemsById = {}, gui = {},
		reason = nil, other = {}, asked = {} }
	if ok and type(result) == "table" then
		mergeBlocks(assets, result)
		for name, key in pairs(result.gui or {}) do
			if assets.textures[key] then
				assets.gui[name] = key
			end
		end
		if type(result.items) == "table" and #result.items > 0 then
			assets.items = result.items -- the creative inventory (in this order)
		end
		assets.available = result.available == true and next(assets.blocks) ~= nil
		assets.reason = result.reason
	else
		assets.reason = "Minecraft has no pictures for us (" .. tostring(result) .. ")"
	end
	world.assets = assets
	if assets.available then
		log(string.format("pictures from Minecraft: %d textured block(s), %d pictures", count(assets.blocks),
			count(assets.textures)))
	else
		log("no pictures from Minecraft - grey blocks (" .. tostring(assets.reason) .. ")")
	end
	renderAll(true) -- all pictures may be new
	assetsChanged:FireAllClients(clientAssets())
end

-- The icons + looks of all items of the creative inventory, in a few calls; the clients get them all together
function loadItemIcons(generation)
	local assets = world.assets
	if not assets or not assets.available then
		return
	end
	local ids = {}
	for _, item in ipairs(assets.items) do
		if not assets.itemsById[item.id] then
			assets.asked["item " .. item.id] = true
			table.insert(ids, item.id)
		end
	end
	for first = 1, #ids, MAX_ASK do
		local batch = {}
		for index = first, math.min(first + MAX_ASK - 1, #ids) do
			table.insert(batch, ids[index])
		end
		local ok, result = pcall(client.Call, client, ASSETS, { items = batch }, { Timeout = 30 })
		if generation ~= world.generation or world.assets ~= assets then
			return
		end
		if ok and type(result) == "table" then
			mergeBlocks(assets, result)
		else
			for _, id in ipairs(batch) do
				assets.asked["item " .. id] = nil -- (asked again when it shows up in an inventory)
			end
		end
	end
	log(string.format("item icons from Minecraft: %d", count(assets.itemsById)))
	afterNewPictures()
end

function afterNewPictures()
	renderAll(false) -- only blocks that were grey so far change
	assetsChanged:FireAllClients(clientAssets())
end
-- endregion

-- region skins (every model with McSkinUser: Roblox characters + the NPCs of Minecraft players)
local skins = {} -- key -> {w, h, pixels}
local userSkins = {} -- user id -> {key, slim, name}
local skinAsks = {} -- user id -> true while asking

local function fetchSkin(userId, set)
	local args: { [string]: any } = { u = userId }
	if set ~= nil then
		args.set = set
	end
	local ok, result = pcall(client.Call, client, SKIN, args, { Timeout = 20 })
	if ok and type(result) == "table" and result.ok == true and type(result.key) == "string" then
		if not skins[result.key] then
			skins[result.key] = decodeTexture(result)
		end
		if skins[result.key] then
			userSkins[userId] = { key = result.key, slim = result.slim == true, name = result.name }
			return true, result
		end
		return false, "skin picture broken"
	end
	return false, if ok and type(result) == "table" then result.reason else tostring(result)
end

local function dress(model)
	local userId = model:GetAttribute("McSkinUser")
	local skin = userSkins[userId]
	if skin and model.Parent then
		Character.setShape(model, skin.slim)
		model:SetAttribute("McSkin", skin.key)
	end
end

local function dressAll(userId)
	for _, item in ipairs(workspace:GetDescendants()) do
		if item:IsA("Model") and item:GetAttribute("McSkinUser") == userId then
			dress(item)
		end
	end
end

local function wantSkin(model)
	local userId = model:GetAttribute("McSkinUser")
	if type(userId) ~= "number" then
		return
	end
	if userSkins[userId] then
		dress(model)
		return
	end
	if skinAsks[userId] then
		return -- dressAll does it when the answer is there
	end
	skinAsks[userId] = true
	task.spawn(function()
		fetchSkin(userId, nil)
		skinAsks[userId] = nil
		dressAll(userId)
	end)
end

-- New NPCs of Minecraft players (PlayerSync builds them): every half second a look for undressed ones
task.spawn(function()
	while true do
		task.wait(0.5)
		local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
		if npcs then
			for _, item in ipairs(npcs:GetDescendants()) do
				if item:IsA("Model") and item:GetAttribute("McSkinUser") ~= nil and item:GetAttribute("McSkin") == nil then
					wantSkin(item)
				end
			end
		end
	end
end)

getSkin.OnServerInvoke = function(_player, key)
	return if type(key) == "string" then skins[key] else nil
end
-- endregion

-- region loading
local function areaChunks(info)
	local list = {}
	local radius = info.radius
	for dx = -radius, radius do
		for dz = -radius, radius do
			table.insert(list, { info.center[1] + dx, info.center[2] + dz, dx * dx + dz * dz })
		end
	end
	table.sort(list, function(a, b)
		return a[3] < b[3] -- the middle first
	end)
	return list
end

--- Loads chunks ({cx, cz} lists) in batches. Returns false if it stopped (error or a newer load started).
local function loadChunks(list, generation)
	for i = 1, #list, CHUNKS_PER_CALL do
		local batch = {}
		for j = i, math.min(i + CHUNKS_PER_CALL - 1, #list) do
			table.insert(batch, { list[j][1], list[j][2] })
		end
		local ok, result = pcall(client.Call, client, CHUNKS, { chunks = batch }, { Timeout = 30 })
		if generation ~= world.generation then
			return false
		end
		if not ok or type(result) ~= "table" then
			warn("[MinecraftWorld] loading chunks failed: " .. tostring(result))
			return false
		end
		for _, data in ipairs(result.chunks or {}) do
			if not data.outside then
				local applied, err = pcall(applyChunk, data)
				if not applied then
					warn("[MinecraftWorld] chunk " .. chunkKey(data.x, data.z) .. ": " .. tostring(err))
				end
			end
		end
	end
	return true
end

local function loadWorld()
	world.generation += 1
	local generation = world.generation
	world.loaded = false
	local info = nil
	local warned = false
	while generation == world.generation do
		local ok, result = pcall(client.Call, client, INFO, nil, { Timeout = 10 })
		if ok and type(result) == "table" and result.version then
			info = result
			break
		end
		if not warned then
			warned = true
			log("waiting for the Minecraft server (" .. tostring(result) .. ")")
		end
		task.wait(3)
	end
	if generation ~= world.generation then
		return
	end
	world.info = info
	for _, chunk in pairs(world.chunks) do
		chunk.folder:Destroy()
	end
	table.clear(world.chunks)
	local started = os.clock()
	local list = areaChunks(info)
	-- The pictures first (small): the chunks are then built with textures right away
	loadAssets(generation)
	task.spawn(loadItemIcons, generation) -- all item icons at the same time as the world (the clients get them at once)
	if generation ~= world.generation then
		return
	end
	if loadChunks(list, generation) then
		world.loaded = true
		local parts = 0
		for _, chunk in pairs(world.chunks) do
			parts += #chunk.folder:GetChildren()
		end
		log(string.format("Minecraft world loaded: %d chunks, %d parts, %.1f s", #list, parts, os.clock() - started))
		onWorldReady()
	else
		task.delay(3, function()
			if generation == world.generation then
				task.spawn(loadWorld) -- try again
			end
		end)
	end
end
-- endregion

-- region changes
local function sectionAt(blockX, blockY, blockZ, create)
	local chunkX, chunkZ = math.floor(blockX / 16), math.floor(blockZ / 16)
	local chunk = world.chunks[chunkKey(chunkX, chunkZ)]
	if not chunk then
		return nil
	end
	local sectionY = math.floor(blockY / 16)
	local section = chunk.sections[sectionY]
	if not section and create then
		local cells = table.create(4096, 0)
		section = { palette = { "minecraft:air" }, cells = cells, parts = {} }
		chunk.sections[sectionY] = section
	end
	return chunk, sectionY, section
end

local function applyBlocks(blocks)
	local dirty = {}
	local names = {}
	for _, block in ipairs(blocks) do
		local x, y, z, name = block[1], block[2], block[3], block[4]
		table.insert(names, name)
		if type(x) == "number" and type(y) == "number" and type(z) == "number" and type(name) == "string" then
			local chunk, sectionY, section = sectionAt(x, y, z, true)
			if chunk and section then
				local paletteIndex = table.find(section.palette, name)
				if not paletteIndex then
					table.insert(section.palette, name)
					paletteIndex = #section.palette
				end
				section.cells[cellIndex(x - chunk.x * 16, y - sectionY * 16, z - chunk.z * 16)] = paletteIndex - 1
				dirty[section] = { chunk, sectionY }
			end
		end
	end
	for section, place in pairs(dirty) do
		renderSection(place[1], place[2], section)
	end
	noticeBlocks(names)
end

local function blockAt(x, y, z)
	local chunk, sectionY, section = sectionAt(x, y, z, false)
	if not chunk or not section then
		return "minecraft:air"
	end
	local index = section.cells[cellIndex(x - chunk.x * 16, y - sectionY * 16, z - chunk.z * 16)]
	return section.palette[(index or 0) + 1] or "minecraft:air"
end

-- region Roblox players as Minecraft players: game mode, inventory, building (mcworld.player / mcworld.edit)
--[[
	Every Roblox player is a Minecraft player in Minecraft (the mod keeps a stand-in for him): his game mode
	(survival / creative / adventure / spectator, changed with /gamemode in the chat) and his inventory live there.
	Right click = "use" (Minecraft decides: open a door, press a button, pull a lever - or place the item in his hand:
	a log lies the way you clicked, a piston faces you), left click = "break" (survival: after the breaking time the
	client counts; the drops go into his inventory). The state comes back with every answer:
	{gm, sel, slots = [46 x (false | {id, n, name, max, bar?})], carried} -> player attribute McGameMode + to his client.
]]
local editTokens = {} -- player -> {tokens, at}
local states = {} -- player -> his state from Minecraft
local busy = {} -- player -> list of waiting inventory jobs (one after the other, in order)
local killedByCommand = {} -- player -> true: Minecraft did the death already (/kill)
local lastHurt = {} -- player -> {cause, at}
local NOCLIP = "McNoclip" -- spectators fly through blocks
pcall(function()
	local physics = game:GetService("PhysicsService")
	physics:RegisterCollisionGroup(NOCLIP)
	physics:CollisionGroupSetCollidable(NOCLIP, "Default", false)
	physics:CollisionGroupSetCollidable(NOCLIP, NOCLIP, false)
end)

local function allowEdit(player)
	local now = os.clock()
	local bucket = editTokens[player] or { tokens = EDITS_PER_SECOND, at = now }
	bucket.tokens = math.min(EDITS_PER_SECOND, bucket.tokens + (now - bucket.at) * EDITS_PER_SECOND)
	bucket.at = now
	editTokens[player] = bucket
	if bucket.tokens < 1 then
		return false
	end
	bucket.tokens -= 1
	return true
end

local function gameModeOf(player)
	local state = states[player]
	return if state and type(state.gm) == "string" then state.gm else "survival"
end

-- the attribute everybody sees (clients: flying, hearts, visibility; PlayerSync) + spectators go through blocks
local function applyGameMode(player)
	local mode = gameModeOf(player)
	pcall(function()
		player:SetAttribute("McGameMode", mode)
	end)
	local character = player.Character
	if character then
		character:SetAttribute("McGameMode", mode)
		local group = if mode == "spectator" then NOCLIP else "Default"
		for _, part in ipairs(character:GetDescendants()) do
			if part:IsA("BasePart") then
				pcall(function()
					part.CollisionGroup = group
				end)
			end
		end
	end
end

local function setState(player, state)
	if type(state) ~= "table" or type(state.slots) ~= "table" then
		return
	end
	states[player] = state
	applyGameMode(player)
	local ids = {}
	for _, stack in ipairs(state.slots) do
		if type(stack) == "table" and type(stack.id) == "string" then
			table.insert(ids, stack.id)
		end
	end
	if type(state.carried) == "table" and type(state.carried.id) == "string" then
		table.insert(ids, state.carried.id)
	end
	noticeItems(ids) -- items nobody has seen yet: their icons
	inventoryRemote:FireClient(player, "state", state)
end

-- where his feet are, in Minecraft blocks
local function feetOf(player)
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	local info = world.info
	if not root or not info then
		return nil
	end
	local scale = info.studsPerBlock
	local position = root.Position
	return { position.X / scale, (position.Y - Character.ROOT_HEIGHT) / scale + info.minY, position.Z / scale }
end

local function vectorList(value)
	if typeof(value) ~= "Vector3" or value.X ~= value.X or value.Y ~= value.Y or value.Z ~= value.Z then
		return nil
	end
	return { value.X, value.Y, value.Z }
end

local function callPlayer(player, op, args)
	args = args or {}
	args.u = player.UserId
	args.name = player.DisplayName
	args.op = op
	local ok, result = pcall(client.Call, client, PLAYER, args, { Timeout = 10 })
	if ok and type(result) == "table" then
		if result.state then
			setState(player, result.state)
		end
		return result
	end
	if Config.Debug then
		warn("[MinecraftWorld] " .. op .. " for " .. player.Name .. " failed: " .. tostring(result))
	end
	return nil
end

-- inventory clicks one after the other (two quick clicks must reach Minecraft in their order)
local function inOrder(player, job)
	local queue = busy[player]
	if queue then
		table.insert(queue, job)
		return
	end
	queue = { job }
	busy[player] = queue
	task.spawn(function()
		while #queue > 0 do
			local next = table.remove(queue, 1)
			pcall(next)
		end
		busy[player] = nil
	end)
end


local function isWhole(value)
	return type(value) == "number" and value == value and math.floor(value) == value and math.abs(value) < 1e7
end

-- The arm swings (PlayerSync sends it to Minecraft: the mannequin swings too)
local function swingArm(player)
	local character = player.Character
	if character then
		character:SetAttribute("McSwing", true)
		task.delay(0.3, function()
			if character.Parent then
				character:SetAttribute("McSwing", false)
			end
		end)
	end
end

local FACE_NAMES = { up = Vector3.new(0, 1, 0), down = Vector3.new(0, -1, 0), north = Vector3.new(0, 0, -1),
	south = Vector3.new(0, 0, 1), east = Vector3.new(1, 0, 0), west = Vector3.new(-1, 0, 0) }

-- Somebody's character stands in the block (Minecraft's hitbox: 0.6 x 1.8 blocks from the feet up)
local function characterInBlock(center, scale)
	for _, other in ipairs(Players:GetPlayers()) do
		local character = other.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if root and character:GetAttribute("McGameMode") ~= "spectator" then
			local p = root.Position
			local half = scale / 2
			local feet = p.Y - Character.ROOT_HEIGHT
			local width = Character.HITBOX.X / 2
			if math.abs(p.X - center.X) < half + width and math.abs(p.Z - center.Z) < half + width
				and feet < center.Y + half and feet + Character.HITBOX.Y > center.Y - half then
				return true
			end
		end
	end
	return false
end

local function itemInfo(id)
	local assets = world.assets
	if type(id) ~= "string" or not assets then
		return nil
	end
	if assets.itemsById[id] then
		return assets.itemsById[id]
	end
	for _, item in ipairs(assets.items or {}) do
		if item.id == id then
			return item
		end
	end
	return nil
end

--[[
	A right click that will surely place a plain block (planks, stone, glass: no rotation, nothing to choose): shown at
	once, Minecraft's answer confirms it. Everything else (logs, stairs, pistons - they turn; doors, levers - they
	are used) waits for Minecraft (a moment), so nothing ever shows wrong.
]]
local function guessPlacement(player, x, y, z, face, slot, sneaking)
	local mode = gameModeOf(player)
	local state = states[player]
	local normal = FACE_NAMES[face]
	if (mode ~= "creative" and mode ~= "survival") or not state or not normal or not slot then
		return
	end
	local stack = state.slots[37 + slot] -- hotbar slot 0-8 = menu slots 36-44
	local item = type(stack) == "table" and itemInfo(stack.id)
	local block = item and item.block
	if type(block) ~= "string" or string.find(block, "[", 1, true) then
		return
	end
	local clicked = blockAt(x, y, z)
	local look = world.assets and world.assets.blocks[clicked]
	-- only on a plain cube that is not used by a click (a crafting table opens, a door opens ...)
	if not look or look.cube ~= true or look.single or string.find(clicked, "[", 1, true)
		or (string.find(baseName(clicked), "_table$") and not sneaking) or baseName(clicked) == "minecraft:jukebox" then
		return
	end
	local px, py, pz = x + normal.X, y + normal.Y, z + normal.Z
	local info = world.info
	if not AIR[baseName(blockAt(px, py, pz))] or py < info.minY or py >= info.maxY then
		return
	end
	local scale = info.studsPerBlock
	if characterInBlock(Vector3.new((px + 0.5) * scale, (py - info.minY + 0.5) * scale, (pz + 0.5) * scale), scale) then
		return
	end
	applyBlocks({ { px, py, pz, block } })
end

-- info = {face = "up" | ..., hit = Vector3 (studs), slot = 0..8, look = Vector3, ground = boolean}
local function onEdit(player, action, x, y, z, info)
	if (action ~= "use" and action ~= "break") or not isWhole(x) or not isWhole(y) or not isWhole(z) then
		return
	end
	info = if type(info) == "table" then info else {}
	local worldInfo = world.info
	if not world.loaded or not worldInfo or y < worldInfo.minY or y >= worldInfo.maxY or not allowEdit(player) then
		return
	end
	local scale = worldInfo.studsPerBlock
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	local center = Vector3.new((x + 0.5) * scale, (y - worldInfo.minY + 0.5) * scale, (z + 0.5) * scale)
	if not root or (center - root.Position).Magnitude > REACH * scale then
		return
	end
	local chunk = sectionAt(x, y, z, false)
	if not chunk then
		return -- outside the area Roblox shows
	end
	local mode = gameModeOf(player)
	if mode == "spectator" or (action == "break" and mode == "adventure") then
		return
	end
	if action == "break" then
		if AIR[baseName(blockAt(x, y, z))] then
			return
		end
		applyBlocks({ { x, y, z, "minecraft:air" } }) -- shown at once; Minecraft confirms (or puts it back)
	end
	swingArm(player)
	local hit = typeof(info.hit) == "Vector3" and info.hit or center
	local slot = if isWhole(info.slot) and info.slot >= 0 and info.slot <= 8 then info.slot else nil
	if action == "use" then
		guessPlacement(player, x, y, z, info.face, slot, character ~= nil and character:GetAttribute("McSneak") == true)
	end
	task.spawn(function()
		local ok, result = pcall(client.Call, client, EDIT, {
			u = player.UserId,
			name = player.DisplayName,
			action = action,
			x = x,
			y = y,
			z = z,
			face = if FACE_NAMES[info.face] then info.face else "up",
			hit = { hit.X / scale, hit.Y / scale + worldInfo.minY, hit.Z / scale },
			look = vectorList(info.look),
			feet = feetOf(player),
			slot = slot,
			sneak = character ~= nil and character:GetAttribute("McSneak") == true,
			ground = info.ground ~= false,
		}, { Timeout = 10 })
		if ok and type(result) == "table" then
			if type(result.blocks) == "table" then
				applyBlocks(result.blocks) -- what Minecraft made of it (also: not broken = back again)
			end
			if result.state then
				setState(player, result.state)
			end
			if result.ok ~= true and Config.Debug then
				log(string.format("%s: %s at %d %d %d - %s", player.Name, action, x, y, z, tostring(result.reason)))
			end
		else
			log(string.format("%s: %s at %d %d %d not possible (%s)", player.Name, action, x, y, z, tostring(result)))
			loadChunks({ { chunk.x, chunk.z } }, world.generation)
		end
	end)
end

editRemote.OnServerEvent:Connect(onEdit)

-- The inventory (E): Minecraft's own clicks, creative items, middle click, Q
inventoryRemote.OnServerEvent:Connect(function(player, op, a, b, c)
	if type(op) ~= "string" or not allowEdit(player) then
		return
	end
	if op == "click" and isWhole(a) and (a == -999 or (a >= 0 and a <= 45)) then
		inOrder(player, function()
			callPlayer(player, "click", { slot = a, button = if b == 1 then 1 else 0, shift = c == true, feet = feetOf(player) })
		end)
	elseif op == "close" then
		inOrder(player, function()
			callPlayer(player, "close", { feet = feetOf(player) })
		end)
	elseif op == "creative" and isWhole(a) and (a == -1 or (a >= 1 and a <= 45)) and (b == nil or (type(b) == "string" and #b < 100)) then
		inOrder(player, function()
			callPlayer(player, "creative", { slot = a, id = b, count = if isWhole(c) then c else 1, feet = feetOf(player) })
		end)
	elseif op == "pick" and isWhole(a) and isWhole(b) and isWhole(c) then
		inOrder(player, function()
			callPlayer(player, "pick", { x = a, y = b, z = c }) -- middle click: what Minecraft gives for that block
		end)
	elseif op == "drop" then
		inOrder(player, function()
			callPlayer(player, "drop", { all = a == true, slot = if isWhole(b) and b >= 0 and b <= 8 then b else nil,
				feet = feetOf(player), look = vectorList(c) })
		end)
	elseif op == "state" then
		inOrder(player, function()
			callPlayer(player, "state")
		end)
	end
end)

-- How fast a block breaks for him (survival: Minecraft knows his item, the block, whether he stands)
local speedAsks = {}
miningSpeed.OnServerInvoke = function(player, x, y, z, slot, ground)
	if not isWhole(x) or not isWhole(y) or not isWhole(z) then
		return nil
	end
	local now = os.clock()
	if now - (speedAsks[player] or 0) < 0.05 then
		return nil
	end
	speedAsks[player] = now
	local ok, result = pcall(client.Call, client, PLAYER, { u = player.UserId, name = player.DisplayName, op = "speed",
		x = x, y = y, z = z, slot = if isWhole(slot) then slot else nil, ground = ground ~= false, feet = feetOf(player) },
		{ Timeout = 10 })
	return if ok and type(result) == "table" and type(result.progress) == "number" then result.progress else nil
end

Players.PlayerRemoving:Connect(function(player)
	if states[player] then
		task.spawn(callPlayer, player, "close") -- the crafting grid goes back into his inventory
	end
	editTokens[player] = nil
	states[player] = nil
	busy[player] = nil
	killedByCommand[player] = nil
	lastHurt[player] = nil
	speedAsks[player] = nil
end)

-- A hit into the air: no block, nobody - Minecraft still swings the arm (the mannequin too)
local swingTokens = {}
swingRemote.OnServerEvent:Connect(function(player)
	local now = os.clock()
	if now - (swingTokens[player] or 0) >= 0.1 then
		swingTokens[player] = now
		swingArm(player)
	end
end)
Players.PlayerRemoving:Connect(function(player)
	swingTokens[player] = nil
end)

-- region health + damage
local function onDied(player)
	if killedByCommand[player] then
		killedByCommand[player] = nil -- Minecraft did it already
		return
	end
	local hurtBy = lastHurt[player]
	local cause = if hurtBy and os.clock() - hurtBy.at < 10 then hurtBy.cause else "other"
	-- Minecraft's death: the message for everybody, the inventory falls out where he died (unless keepInventory)
	callPlayer(player, "died", { feet = feetOf(player), cause = cause })
end

local function setupHealth(character)
	local humanoid = character:FindFirstChildOfClass("Humanoid") or character:WaitForChild("Humanoid", 10)
	local player = Players:GetPlayerFromCharacter(character)
	if player then
		character:SetAttribute("McSkinUser", player.UserId)
		wantSkin(character)
		applyGameMode(player)
		task.spawn(callPlayer, player, "state") -- his game mode + inventory from Minecraft
	end
	if humanoid then
		humanoid.MaxHealth = MAX_HEALTH
		humanoid.Health = MAX_HEALTH
		if player then
			humanoid.Died:Connect(function()
				onDied(player)
			end)
		end
	end
end

local function watchPlayer(player: any)
	if typeof(player) ~= "Instance" then
		return -- (the test runs with fake players)
	end
	local real = player :: Player
	real.CharacterAdded:Connect(setupHealth)
	if real.Character then
		task.spawn(setupHealth, real.Character)
	end
end
Players.PlayerAdded:Connect(watchPlayer)
for _, player in ipairs(Players:GetPlayers()) do
	watchPlayer(player)
end

-- Creative and spectator players cannot be hurt (Minecraft)
local function hurt(player, amount, from, cause)
	local character = player.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local mode = gameModeOf(player)
	if not humanoid or humanoid.Health <= 0 or amount <= 0 or mode == "creative" or mode == "spectator" then
		return
	end
	lastHurt[player] = { cause = cause, at = os.clock() }
	humanoid:TakeDamage(amount)
	Character.flashRed(character)
	hurtRemote:FireClient(player, amount, from)
end

-- Minecraft: falling more than 3 blocks hurts 1 per block more (not while flying)
fallRemote.OnServerEvent:Connect(function(player, blocks)
	local character = player.Character
	if type(blocks) == "number" and blocks == blocks and blocks > 3
		and not (character and character:GetAttribute("McFlying") == true) then
		hurt(player, math.ceil(math.min(blocks, 400) - 3), nil, "fall")
	end
end)

-- A Roblox player hits a Minecraft player's NPC: Minecraft does the damage (with knockback from our mannequin)
local attackedAt = {}
attackRemote.OnServerEvent:Connect(function(player, model)
	local npcFolder = workspace:FindFirstChild("BridgeRemotePlayers")
	if typeof(model) ~= "Instance" or not model:IsA("Model") or not npcFolder or not model:IsDescendantOf(npcFolder)
		or gameModeOf(player) == "spectator" then
		return
	end
	local target = model:GetAttribute("McUserId")
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	local npcRoot = model:FindFirstChild("HumanoidRootPart")
	local scale = world.info and world.info.studsPerBlock or 3
	if type(target) ~= "number" or not root or not npcRoot
		or (root.Position - npcRoot.Position).Magnitude > (ATTACK_REACH + 1) * scale then
		return
	end
	local now = os.clock()
	if now - (attackedAt[player] or 0) < 1 / ATTACKS_PER_SECOND then
		return
	end
	attackedAt[player] = now
	swingArm(player)
	task.spawn(function()
		local ok, result = pcall(client.Call, client, HURT, { target = target, amount = 1, attacker = player.UserId },
			{ Timeout = 10 })
		if not ok and Config.Debug then
			warn("[MinecraftWorld] hit not sent: " .. tostring(result))
		end
	end)
end)

Players.PlayerRemoving:Connect(function(player)
	attackedAt[player] = nil
end)

-- Direct messages from the mod: a Minecraft player hit our mannequin / his inventory changed (picked something up)
client.MessageReceived:Connect(function(message)
	local content = message.Content
	if type(content) ~= "table" then
		return
	end
	if content.type == "mc.hurt" then
		local from = nil
		if type(content.from) == "table" then
			from = Vector3.new(tonumber(content.from[1]) or 0, tonumber(content.from[2]) or 0, tonumber(content.from[3]) or 0)
		end
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				hurt(player, math.clamp(tonumber(content.amount) or 0, 0, 100), from, "attack")
			end
		end
	elseif content.type == "mc.player" then
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				setState(player, content.state)
			end
		end
	end
end)
-- endregion

-- Sneaking / sprinting / flying: attributes on the character - the client scripts show the pose, PlayerSync sends it
moveRemote.OnServerEvent:Connect(function(player, sneak, sprint, pitch, flying)
	local character = player.Character
	if character then
		local mode = gameModeOf(player)
		character:SetAttribute("McSneak", sneak == true)
		character:SetAttribute("McSprint", sprint == true and sneak ~= true)
		character:SetAttribute("McFlying", flying == true and (mode == "creative" or mode == "spectator"))
		if type(pitch) == "number" and pitch == pitch then
			character:SetAttribute("McPitch", math.clamp(pitch, -1.58, 1.58)) -- the head looks up / down (radians)
		end
	end
end)

-- region chat + commands
local chatTokens = {}
local function allowChat(player)
	local now = os.clock()
	local bucket = chatTokens[player] or { tokens = CHAT_PER_5S, at = now }
	bucket.tokens = math.min(CHAT_PER_5S, bucket.tokens + (now - bucket.at) * CHAT_PER_5S / 5)
	bucket.at = now
	chatTokens[player] = bucket
	if bucket.tokens < 1 then
		return false
	end
	bucket.tokens -= 1
	return true
end
Players.PlayerRemoving:Connect(function(player)
	chatTokens[player] = nil
end)

local function reply(player, lines)
	chatRemote:FireClient(player, "reply", lines)
end

local function setSkin(player, name)
	local ok, result = fetchSkin(player.UserId, name)
	if ok then
		dressAll(player.UserId)
		reply(player, { if name == "" then "Skin: Minecraft-Standard" else "Skin: " .. tostring(result.name or name) })
	else
		reply(player, { "Skin nicht gefunden: " .. tostring(result) })
	end
end

local function runCommand(player, command)
	local ok, result = pcall(client.Call, client, COMMAND, { u = player.UserId, name = player.DisplayName, command = command },
		{ Timeout = 20 })
	if not ok or type(result) ~= "table" then
		reply(player, { "Minecraft antwortet nicht: " .. tostring(result) })
		return
	end
	local lines = {}
	for _, line in ipairs(if type(result.output) == "table" then result.output else {}) do
		if type(line) == "string" then
			table.insert(lines, line)
		end
	end
	if #lines == 0 then
		table.insert(lines, "/" .. command)
	end
	reply(player, lines)
	if result.state then
		setState(player, result.state) -- /gamemode, /give, /clear ...
	end
	if result.killed == true then
		-- /kill: Minecraft did his death (message, items) - the character dies too, without a second death
		local humanoid = player.Character and player.Character:FindFirstChildOfClass("Humanoid")
		if humanoid and humanoid.Health > 0 then
			killedByCommand[player] = true
			humanoid.Health = 0
		end
		return
	end
	-- the command moved his mannequin (/tp @s ...): his character goes there too (teleport = root part at 3 studs)
	local teleport = result.teleport
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	if type(teleport) == "table" and root then
		local feet = Vector3.new(tonumber(teleport[1]) or 0, (tonumber(teleport[2]) or 0) - 3, tonumber(teleport[3]) or 0)
		local turn = root.CFrame - root.Position
		character:PivotTo(CFrame.new(feet + Vector3.new(0, Character.ROOT_HEIGHT, 0)) * turn)
	end
end

chatRemote.OnServerEvent:Connect(function(player, text)
	if type(text) ~= "string" then
		return
	end
	text = string.gsub(string.gsub(text, "^%s+", ""), "%s+$", "")
	if text == "" or utf8.len(text) == nil or #text > MAX_CHAT * 4 or not allowChat(player) then
		return
	end
	if string.sub(text, 1, 1) == "/" then
		local word, rest = string.match(text, "^/(%S+)%s*(.-)$")
		if word and string.lower(word) == "skin" then
			task.spawn(setSkin, player, rest or "")
		elseif word then
			task.spawn(runCommand, player, string.sub(text, 2))
		end
		return
	end
	task.spawn(function()
		local ok, err = pcall(client.Call, client, CHAT,
			{ u = player.UserId, name = player.DisplayName, text = text, label = Config.Label }, { Timeout = 10 })
		if not ok and Config.Debug then
			warn("[MinecraftWorld] chat not sent: " .. tostring(err))
		end
	end)
end)

client:Subscribe(nil, CHAT, function(data)
	if type(data) == "table" and type(data.text) == "string" then
		chatRemote:FireAllClients("mc", tostring(data.kind or "chat"), data.text, data.from)
	end
end)

-- "/..." are Minecraft commands: never into the Roblox chat of the others (the client hides it from the writer too)
task.spawn(function()
	local ok, channels = pcall(function()
		return game:GetService("TextChatService"):WaitForChild("TextChannels", 60)
	end)
	if not ok or not channels then
		return
	end
	local function guard(channel)
		if channel:IsA("TextChannel") then
			channel.ShouldDeliverCallback = function(message)
				return string.sub(message.Text or "", 1, 1) ~= "/"
			end
		end
	end
	for _, channel in ipairs(channels:GetChildren()) do
		guard(channel)
	end
	channels.ChildAdded:Connect(guard)
end)
-- endregion
-- endregion

-- region items lying in the world (Minecraft's item entities: everybody sees them, whoever touches one first gets it -
-- a Minecraft player or a Roblox player, decided in Minecraft: there is only one of each)
local itemFolder = workspace:FindFirstChild("MinecraftItems") or Instance.new("Folder")
itemFolder.Name = "MinecraftItems"
itemFolder.Parent = workspace
local itemAnchors = {} -- entity id (text) -> invisible Part where it lies; the clients draw the item there

client:Subscribe(nil, ITEMS, function(data)
	local info = world.info
	if type(data) ~= "table" or type(data.items) ~= "table" or not info then
		return
	end
	local scale, minY = info.studsPerBlock, info.minY
	local seen, newIds = {}, {}
	for _, entry in ipairs(data.items) do
		if type(entry) == "table" and type(entry[1]) == "number" and type(entry[2]) == "string" then
			local key = tostring(entry[1])
			seen[key] = true
			local anchor = itemAnchors[key]
			if not anchor then
				anchor = Instance.new("Part")
				anchor.Name = key
				anchor.Anchored = true
				anchor.CanCollide = false
				anchor.CanQuery = false
				anchor.CanTouch = false
				anchor.Transparency = 1
				anchor.Size = Vector3.one * 0.2
				itemAnchors[key] = anchor
				table.insert(newIds, entry[2])
			end
			anchor:SetAttribute("McItem", entry[2])
			anchor:SetAttribute("McCount", math.max(1, math.floor(tonumber(entry[3]) or 1)))
			anchor.CFrame = CFrame.new((tonumber(entry[4]) or 0) * scale, ((tonumber(entry[5]) or 0) - minY) * scale,
				(tonumber(entry[6]) or 0) * scale)
			anchor.Parent = itemFolder
		end
	end
	for key, anchor in pairs(itemAnchors) do
		if not seen[key] then
			anchor:Destroy() -- picked up (by anybody), merged or gone
			itemAnchors[key] = nil
		end
	end
	noticeItems(newIds)
end, { Latest = true })
-- endregion

client:Subscribe(nil, CHANGES, function(data)
	if type(data) ~= "table" then
		return
	end
	if data.reload then
		log("Minecraft says: load everything again")
		task.spawn(loadWorld)
		return
	end
	if not world.info then
		return -- the first load gets the current state anyway
	end
	if type(data.blocks) == "table" then
		applyBlocks(data.blocks)
	end
	if type(data.chunks) == "table" then
		local list = {}
		for _, pair in ipairs(data.chunks) do
			if world.chunks[chunkKey(pair[1], pair[2])] then
				table.insert(list, { pair[1], pair[2] })
			end
		end
		task.spawn(loadChunks, list, world.generation)
	end
end)

-- After a lost connection the world may have changed meanwhile: load it again
local wasOffline = false
client.Disconnected:Connect(function()
	wasOffline = true
end)
client.Connected:Connect(function()
	if wasOffline then
		wasOffline = false
		log("connection back - loading the world again")
		task.spawn(loadWorld)
	end
end)
-- endregion

log("started - Bridge server " .. client.Server)
loadWorld()
