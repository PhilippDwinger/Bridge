--[[
	MinecraftWorld - the Minecraft world in Roblox (Script in ServerScriptService)

	The Minecraft server (mod BridgeGameSync) is a Bridge client too. This game server:
	  1. asks it for the world (command mcworld.info + mcworld.chunks) and builds every block as a grey placeholder
	     cube - neighbouring blocks are merged into bigger parts (greedy meshing), so a flat map is only a few parts
	  2. follows every change (topic mcworld.changes): placed / broken blocks, whole chunks after big changes, a full
	     reload after a Minecraft restart or a lost connection
	  3. players: the script PlayerSync (same game) shows the Minecraft players with a Roblox avatar and sends ours to
	     Minecraft (shown there as mannequins). Same coordinates: 1 block = 3 studs, the lowest Minecraft layer at y 0.

	Needs in ServerStorage: Bridge, MinecraftWorldConfig, MinecraftWorldClient (shared Bridge client), PlayerSyncConfig.
]]
local Players = game:GetService("Players")
local ServerStorage = game:GetService("ServerStorage")

local Config = require(ServerStorage:WaitForChild("MinecraftWorldConfig"))
local client = require(ServerStorage:WaitForChild("MinecraftWorldClient"))

local INFO = Config.WorldPrefix .. ".info"
local CHUNKS = Config.WorldPrefix .. ".chunks"
local CHANGES = Config.WorldPrefix .. ".changes"
local CHUNKS_PER_CALL = Config.ChunksPerCall or 4
local WAIT_FOR_WORLD = 15 -- seconds; after that players spawn on a waiting platform until the world is there
local AIR = { ["minecraft:air"] = true, ["minecraft:cave_air"] = true, ["minecraft:void_air"] = true }

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
}

local function log(...)
	print("[MinecraftWorld]", ...)
end

local function chunkKey(x, z)
	return x .. "," .. z
end

-- region blocks -> parts
-- One place that decides how a Minecraft block looks. For now every block is the same grey cube.
local function renderKey(name)
	if name == nil or AIR[name] then
		return nil
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
	for _, block in ipairs(blocks) do
		local x, y, z, name = block[1], block[2], block[3], block[4]
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
end

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
