--[[
	MinecraftWorld - the Minecraft world in Roblox (Script in ServerScriptService)

	The Minecraft server (mod BridgeGameSync) is a Bridge client too. This game server:
	  1. asks it for the world (command mcworld.info + mcworld.chunks) and builds every block as a grey placeholder
	     cube - neighbouring blocks are merged into bigger parts (greedy meshing), so a flat map is only a few parts
	  2. follows every change (topic mcworld.changes): placed / broken blocks, whole chunks after big changes, a full
	     reload after a Minecraft restart or a lost connection
	  3. players: the script PlayerSync (same game) shows the Minecraft players with a Roblox avatar and sends ours to
	     Minecraft (shown there as mannequins). Same coordinates: 1 block = 3 studs, the lowest Minecraft layer at y 0.
	  4. textures + items (command mcworld.assets): pictures from the Minecraft game itself - textured blocks (for now
	     the grass block) get their own parts with a Texture per side; the client script MinecraftClient turns the
	     pixels into images (EditableImage, they only exist on the client) and shows hotbar + inventory
	  5. building (RemoteEvent ReplicatedStorage.MinecraftWorld.Edit -> command mcworld.edit): Roblox players place and
	     break blocks like in creative mode; shown here at once, Minecraft confirms over mcworld.changes
	  6. health like Minecraft (20 = 10 hearts): fall damage (Fall), hitting a Minecraft player's NPC (Attack ->
	     command mcworld.hurt), Minecraft players hitting our mannequins (direct message "mc.hurt" from the mod)

	Needs in ServerStorage: Bridge, MinecraftWorldConfig, MinecraftWorldClient (shared Bridge client), PlayerSyncConfig.
]]
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")

local Bridge = require(ServerStorage:WaitForChild("Bridge"))
local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))
local client = require(ServerStorage:WaitForChild("MinecraftWorldClient"))

local INFO = Config.WorldPrefix .. ".info"
local CHUNKS = Config.WorldPrefix .. ".chunks"
local CHANGES = Config.WorldPrefix .. ".changes"
local ASSETS = Config.WorldPrefix .. ".assets"
local EDIT = Config.WorldPrefix .. ".edit"
local HURT = Config.WorldPrefix .. ".hurt"
local MAX_HEALTH = 20 -- Minecraft: 10 hearts
local ATTACK_REACH = 5 -- blocks (Minecraft creative 5, survival 3) + a little slack below
local ATTACKS_PER_SECOND = 4
local CHUNKS_PER_CALL = Config.ChunksPerCall or 4
local WAIT_FOR_WORLD = 15 -- seconds; after that players spawn on a waiting platform until the world is there
local REACH = 7 -- blocks from the character to a block it changes (Minecraft creative: 5 from the eyes, + slack)
local EDITS_PER_SECOND = 12 -- per player
local AIR = { ["minecraft:air"] = true, ["minecraft:cave_air"] = true, ["minecraft:void_air"] = true }
-- Without pictures from Minecraft (old mod / dedicated server) the items are still there, with a plain icon
local DEFAULT_ITEMS = { { id = "minecraft:grass_block", name = "Grass Block", block = "minecraft:grass_block" } }
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
local editRemote = remote("RemoteEvent", "Edit") -- client wants: (action "place" | "break", x, y, z, item id)
local moveRemote = remote("RemoteEvent", "Move") -- client says: (sneaking, sprinting) - shown to everybody + Minecraft
local attackRemote = remote("RemoteEvent", "Attack") -- client: (NPC model) hits a Minecraft player
local fallRemote = remote("RemoteEvent", "Fall") -- client: (blocks fallen) - Minecraft's fall damage
local hurtRemote = remote("RemoteEvent", "Hurt") -- server -> client: (amount, from position or nil) red flash, knockback

local function log(...)
	print("[MinecraftWorld]", ...)
end

local function chunkKey(x, z)
	return x .. "," .. z
end

-- region blocks -> parts
-- One place that decides how a Minecraft block looks: every full-cube block with pictures from Minecraft gets its own
-- parts with textures, all other blocks (slabs, flowers, ...) are the same grey cube.
local function renderKey(name)
	if name == nil or AIR[name] then
		return nil
	end
	local assets = world.assets
	if assets and assets.blocks[name] then
		return name
	end
	return "placeholder"
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
					local function same(cx, cy, cz)
						local i = cellIndex(cx, cy, cz)
						return keys[i] == key and not done[i]
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

local function renderSection(chunk, sectionY, section)
	for _, part in ipairs(section.parts) do
		part:Destroy()
	end
	table.clear(section.parts)
	local scale = world.info.studsPerBlock
	local minY = world.info.minY
	for _, box in ipairs(meshSection(section)) do
		local blockX = chunk.x * 16 + box.x
		local blockY = sectionY * 16 + box.y
		local blockZ = chunk.z * 16 + box.z
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
		local look = world.assets and world.assets.blocks[box.key]
		if look then
			-- Textured block: the colour shows until the client has made the pictures; one tile = one block.
			-- Glass / leaves: the part is invisible, only the pictures (with their holes) show.
			part.Name = box.key
			part.Color = Color3.fromRGB(look.color[1], look.color[2], look.color[3])
			if look.transparent then
				part.Transparency = 1
				part.CastShadow = false
			end
			for _, face in ipairs(FACES) do
				local texture = Instance.new("Texture")
				texture.Name = "McTexture"
				texture.Face = face[1]
				texture.StudsPerTileU = scale
				texture.StudsPerTileV = scale
				texture:SetAttribute("McTexture", look.faces[face[2]])
				texture.Parent = part
			end
		end
		part.Parent = chunk.folder
		table.insert(section.parts, part)
	end
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

local function renderAll()
	for _, chunk in pairs(world.chunks) do
		for sectionY, section in pairs(chunk.sections) do
			renderSection(chunk, sectionY, section)
		end
	end
end

-- Blocks Minecraft has not sent pictures for yet (they appear in the world): ask for them in one call, then build again
local askQueue = {}
local askScheduled = false
local mergeBlocks -- below (adds an assets answer)
local afterNewPictures -- below (re-render + tell the clients)

local function noticeBlocks(names)
	local assets = world.assets
	if not assets or not assets.available then
		return
	end
	for _, name in ipairs(names) do
		if type(name) == "string" and not AIR[name] and not assets.blocks[name] and not assets.other[name]
			and not assets.asked[name] then
			assets.asked[name] = true
			table.insert(askQueue, name)
		end
	end
	if #askQueue == 0 or askScheduled then
		return
	end
	askScheduled = true
	task.delay(0.3, function()
		askScheduled = false
		local list = {}
		while #askQueue > 0 and #list < MAX_ASK do
			table.insert(list, table.remove(askQueue, 1))
		end
		local ok, result = pcall(client.Call, client, ASSETS, { blocks = list }, { Timeout = 20 })
		if world.assets ~= assets then
			return -- everything was loaded again meanwhile
		end
		if ok and type(result) == "table" then
			mergeBlocks(assets, result)
			for _, name in ipairs(list) do
				if not assets.blocks[name] then
					assets.other[name] = true
				end
			end
			afterNewPictures()
		else
			for _, name in ipairs(list) do
				assets.asked[name] = nil -- try again when it shows up next time
			end
		end
		if #askQueue > 0 then
			noticeBlocks({})
		end
	end)
end

local function applyChunk(data)
	local key = chunkKey(data.x, data.z)
	local old = world.chunks[key]
	if old then
		old.folder:Destroy()
	end
	local folder = Instance.new("Folder")
	folder.Name = "Chunk " .. key
	local chunk = { x = data.x, z = data.z, sections = {}, folder = folder }
	for _, sectionData in ipairs(data.sections or {}) do
		local section = decodeSection(sectionData)
		noticeBlocks(section.palette)
		chunk.sections[sectionData.y] = section
		renderSection(chunk, sectionData.y, section)
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

-- Adds textures + blocks of an assets answer. Blocks whose pictures did not all arrive count as "other" (grey).
function mergeBlocks(assets, result)
	for key, texture in pairs(result.textures or {}) do
		assets.textures[key] = decodeTexture(texture)
	end
	for name, look in pairs(result.blocks or {}) do
		local complete = type(look) == "table" and look.cube == true and type(look.faces) == "table"
		if complete then
			for _, face in ipairs(FACES) do
				if not assets.textures[look.faces[face[2]]] then
					complete = false
				end
			end
		end
		if complete then
			assets.blocks[name] = look
		else
			assets.other[name] = true
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
	local ok, result = pcall(client.Call, client, ASSETS, nil, { Timeout = 30 })
	if generation ~= world.generation then
		return
	end
	local assets = { available = false, textures = {}, blocks = {}, items = DEFAULT_ITEMS, gui = {}, reason = nil,
		other = {}, asked = {} }
	if ok and type(result) == "table" then
		mergeBlocks(assets, result)
		for name, key in pairs(result.gui or {}) do
			if assets.textures[key] then
				assets.gui[name] = key
			end
		end
		if type(result.items) == "table" and #result.items > 0 then
			assets.items = result.items
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
	renderAll()
	assetsChanged:FireAllClients(clientAssets())
end

function afterNewPictures()
	renderAll()
	assetsChanged:FireAllClients(clientAssets())
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

-- region building (Roblox players, creative mode)
local editTokens = {} -- player -> {tokens, at}

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

Players.PlayerRemoving:Connect(function(player)
	editTokens[player] = nil
end)

local function itemById(id)
	for _, item in ipairs(world.assets and world.assets.items or DEFAULT_ITEMS) do
		if item.id == id then
			return item
		end
	end
	return nil
end

-- Somebody's character stands in the block (feet 3 studs under the root part, head 2 above)
local function characterInBlock(center, scale)
	for _, other in ipairs(Players:GetPlayers()) do
		local character = other.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if root then
			local p = root.Position
			local half = scale / 2
			if math.abs(p.X - center.X) < half + 1 and math.abs(p.Z - center.Z) < half + 1
				and p.Y - 3 < center.Y + half and p.Y + 2 > center.Y - half then
				return true
			end
		end
	end
	return false
end

local function isWhole(value)
	return type(value) == "number" and value == value and math.floor(value) == value and math.abs(value) < 1e7
end

local function onEdit(player, action, x, y, z, itemId)
	if (action ~= "place" and action ~= "break") or not isWhole(x) or not isWhole(y) or not isWhole(z) then
		return
	end
	local info = world.info
	if not world.loaded or not info or y < info.minY or y >= info.maxY or not allowEdit(player) then
		return
	end
	local scale = info.studsPerBlock
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	local center = Vector3.new((x + 0.5) * scale, (y - info.minY + 0.5) * scale, (z + 0.5) * scale)
	if not root or (center - root.Position).Magnitude > REACH * scale then
		return
	end
	local chunk = sectionAt(x, y, z, false)
	if not chunk then
		return -- outside the area Roblox shows
	end
	local current = blockAt(x, y, z)
	local name
	if action == "break" then
		if AIR[current] then
			return
		end
		name = "minecraft:air"
	else
		local item = itemById(itemId)
		if not item or type(item.block) ~= "string" or not AIR[current] or characterInBlock(center, scale) then
			return
		end
		name = item.block
	end
	-- Shown at once; Minecraft confirms it over mcworld.changes (the same block again)
	applyBlocks({ { x, y, z, name } })
	task.spawn(function()
		local ok, result = pcall(client.Call, client, EDIT, {
			action = action,
			x = x,
			y = y,
			z = z,
			block = if action == "place" then name else nil,
			player = player.Name,
		}, { Timeout = 10 })
		if not ok or type(result) ~= "table" or result.ok ~= true then
			-- Minecraft said no (somebody stands there, ...) or is not there: show what really is there
			log(string.format("%s: %s at %d %d %d not possible (%s)", player.Name, action, x, y, z,
				tostring(if ok and type(result) == "table" then result.reason else result)))
			loadChunks({ { chunk.x, chunk.z } }, world.generation)
		end
	end)
end

editRemote.OnServerEvent:Connect(onEdit)

-- region health + damage
local function setupHealth(character)
	local humanoid = character:FindFirstChildOfClass("Humanoid") or character:WaitForChild("Humanoid", 10)
	if humanoid then
		humanoid.MaxHealth = MAX_HEALTH
		humanoid.Health = MAX_HEALTH
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

local function hurt(player, amount, from)
	local character = player.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	if not humanoid or humanoid.Health <= 0 or amount <= 0 then
		return
	end
	humanoid:TakeDamage(amount)
	hurtRemote:FireClient(player, amount, from)
end

-- Minecraft: falling more than 3 blocks hurts 1 per block more
fallRemote.OnServerEvent:Connect(function(player, blocks)
	if type(blocks) == "number" and blocks == blocks and blocks > 3 then
		hurt(player, math.ceil(math.min(blocks, 400) - 3), nil)
	end
end)

-- A Roblox player hits a Minecraft player's NPC: Minecraft does the damage (with knockback from our mannequin)
local attackedAt = {}
attackRemote.OnServerEvent:Connect(function(player, model)
	local npcFolder = workspace:FindFirstChild("BridgeRemotePlayers")
	if typeof(model) ~= "Instance" or not model:IsA("Model") or not npcFolder or not model:IsDescendantOf(npcFolder) then
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

-- A Minecraft player hit our mannequin: the mod sends a direct message to this game server
client.MessageReceived:Connect(function(message)
	local content = message.Content
	if type(content) ~= "table" or content.type ~= "mc.hurt" then
		return
	end
	local from = nil
	if type(content.from) == "table" then
		from = Vector3.new(tonumber(content.from[1]) or 0, tonumber(content.from[2]) or 0, tonumber(content.from[3]) or 0)
	end
	for _, player in ipairs(Players:GetPlayers()) do
		if player.UserId == content.u then
			hurt(player, math.clamp(tonumber(content.amount) or 0, 0, 100), from)
		end
	end
end)
-- endregion

-- Sneaking / sprinting: attributes on the character - the client scripts show the pose, PlayerSync sends it to Minecraft
moveRemote.OnServerEvent:Connect(function(player, sneak, sprint)
	local character = player.Character
	if character then
		character:SetAttribute("McSneak", sneak == true)
		character:SetAttribute("McSprint", sprint == true and sneak ~= true)
	end
end)
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
