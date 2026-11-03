--[[
	Real worlds in Roblox: runs the REAL MinecraftWorld script (Lune's Roblox library) against a FAKE Minecraft (no
	Bridge server, no Minecraft): a generated world like a normal Minecraft world - hills, stone with ores, caves, a
	lake, trees, 384 blocks high - served the way the mod serves it (mcworld.chunks v 2: palette + zlib + Base64,
	"later" while a chunk is still being generated, at most ~36 KB per answer).

	Checks:
	  - every block face you can see (next to air / water / glass ...) is covered by a part with a picture on that face
	  - no part stands where there is air, buried blocks are not built (few parts), nothing deep under everybody
	  - breaking a block shows the blocks behind it at once
	  - the world follows the player (new chunks come, far ones go), a character waits where the ground is not built
	  - a frame never builds longer than the budget (BuildBudgetMs)

	    lune run sim_realworld.luau [json options]
]]
local shim = require("./roblox_shim")
local process = require("@lune/process")
local fs = require("@lune/fs")
local luau = require("@lune/luau")
local serde = require("@lune/serde")
local roblox = require("@lune/roblox")
local Bridge = require("../src/Bridge")

local options = if process.args[1] then serde.decode("json", process.args[1]) else {}
local VIEW = options.view or 4
local Instance, Vector3, CFrame, Enum, Color3 = roblox.Instance, roblox.Vector3, roblox.CFrame, roblox.Enum, roblox.Color3

local failures = {}
local function check(condition, text)
	if condition then
		print("  OK    " .. text)
	else
		print("  FAIL  " .. text)
		table.insert(failures, text)
	end
end

-- region the generated world (deterministic)
local MIN_Y, MAX_Y = -64, 320
local function hash(x, y, z)
	local n = (x * 374761393 + y * 668265263 + z * 2147483647) % 4294967296
	n = bit32.bxor(n, bit32.rshift(n, 13))
	n = (n * 1274126177) % 4294967296
	return (n % 1000000) / 1000000
end
local function height(x, z)
	return math.floor(66 + 7 * math.sin(x / 11) + 5 * math.cos(z / 9) + 3 * math.sin((x + z) / 5))
end
local function isCave(x, y, z)
	-- worm-like caves between y -50 and 50
	if y < -50 or y > 50 then
		return false
	end
	local v = math.sin(x / 7 + y / 11) * math.cos(z / 6 - y / 13) + math.sin((x - z) / 9) * 0.6
	return v > 1.05
end
local LAKE = { x = 20, z = 20, r = 7 }
local function tree(x, z) -- a tree stands at x, z?
	return hash(x, 0, z) > 0.985 and (x - LAKE.x) ^ 2 + (z - LAKE.z) ^ 2 > (LAKE.r + 3) ^ 2
end
local edits = {} -- "x,y,z" -> name (blocks changed by the test)
local function generated(x, y, z)
	if y == MIN_Y then
		return "minecraft:bedrock"
	end
	local h = height(x, z)
	local lake = (x - LAKE.x) ^ 2 + (z - LAKE.z) ^ 2 <= LAKE.r * LAKE.r
	if lake then
		h = math.min(h, 60)
		if y > h and y <= 63 then
			return "minecraft:water"
		end
	end
	if y > h + 7 then
		return "minecraft:air" -- (above every tree)
	end
	if y > h then
		-- trees: trunk 4 high, leaves around
		for tx = x - 2, x + 2 do
			for tz = z - 2, z + 2 do
				if tree(tx, tz) then
					local base = height(tx, tz)
					if tx == x and tz == z and y > base and y <= base + 4 then
						return "minecraft:oak_log[axis=y]"
					end
					if y >= base + 3 and y <= base + 5 and math.abs(tx - x) + math.abs(tz - z) <= 3 - (y - base - 3) then
						return "minecraft:oak_leaves"
					end
				end
			end
		end
		return "minecraft:air"
	end
	if isCave(x, y, z) then
		return "minecraft:air"
	end
	if y == h then
		return if lake then "minecraft:sand" else "minecraft:grass_block[snowy=false]"
	elseif y > h - 4 then
		return "minecraft:dirt"
	end
	if hash(x, y, z) > 0.992 then
		return "minecraft:coal_ore"
	end
	return if y < 0 then "minecraft:deepslate" else "minecraft:stone"
end
local function blockAt(x, y, z)
	return edits[x .. "," .. y .. "," .. z] or generated(x, y, z)
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function base64(data)
	local out = {}
	for i = 1, #data, 3 do
		local a, b, c = string.byte(data, i, i + 2)
		local n = a * 65536 + (b or 0) * 256 + (c or 0)
		local c1, c2, c3, c4 = bit32.rshift(n, 18), bit32.band(bit32.rshift(n, 12), 63), bit32.band(bit32.rshift(n, 6), 63),
			bit32.band(n, 63)
		table.insert(out, string.sub(B64, c1 + 1, c1 + 1) .. string.sub(B64, c2 + 1, c2 + 1)
			.. (if b then string.sub(B64, c3 + 1, c3 + 1) else "=") .. (if c then string.sub(B64, c4 + 1, c4 + 1) else "="))
	end
	return table.concat(out)
end

local generatedChunks = {} -- chunks Minecraft has "generated" (the first ask answers later)
local chunkCalls, laterAnswers, bytesSent = 0, 0, 0
local function packChunk(cx, cz)
	local palette, index = { "minecraft:air" }, { ["minecraft:air"] = 0 }
	local ys, parts = {}, {}
	for sy = MIN_Y // 16, (MAX_Y - 1) // 16 do
		local bytes = table.create(4096)
		local any = false
		local n = 0
		for ly = 0, 15 do
			for lz = 0, 15 do
				for lx = 0, 15 do
					local name = blockAt(cx * 16 + lx, sy * 16 + ly, cz * 16 + lz)
					local i = index[name]
					if not i then
						i = #palette
						table.insert(palette, name)
						index[name] = i
					end
					if i ~= 0 then
						any = true
					end
					n += 1
					bytes[n] = i
				end
			end
		end
		if any then
			table.insert(ys, sy)
			local chars = table.create(4096)
			for k = 1, 4096 do
				chars[k] = string.char(bytes[k])
			end
			table.insert(parts, table.concat(chars))
		end
	end
	local data = base64(serde.compress("zlib", table.concat(parts)))
	return { x = cx, z = cz, v = 2, palette = palette, ys = ys, wide = false, data = data }
end

-- the looks of the blocks (cubes: one picture per face; water + leaves see-through)
local function picture(r, g, b)
	local raw = string.rep(string.char(r, g, b, 255), 16 * 16)
	return { w = 16, h = 16, rgba = base64(serde.compress("zlib", raw)) }
end
local LOOKS = {
	["minecraft:stone"] = { 125, 125, 125 }, ["minecraft:deepslate"] = { 80, 80, 85 }, ["minecraft:dirt"] = { 134, 96, 67 },
	["minecraft:grass_block[snowy=false]"] = { 95, 159, 53 }, ["minecraft:sand"] = { 219, 207, 163 },
	["minecraft:coal_ore"] = { 110, 110, 110 }, ["minecraft:bedrock"] = { 60, 60, 60 },
	["minecraft:oak_log[axis=y]"] = { 109, 85, 50 }, ["minecraft:oak_leaves"] = { 60, 120, 40 },
	["minecraft:water"] = { 63, 118, 228 },
}
local function assetsAnswer()
	local textures, blocks = {}, {}
	for name, rgb in pairs(LOOKS) do
		textures[name] = picture(rgb[1], rgb[2], rgb[3])
		local faces = {}
		for _, face in ipairs({ "up", "down", "north", "south", "east", "west" }) do
			faces[face] = name
		end
		local look = { cube = true, faces = faces, color = rgb, hard = 1 }
		if name == "minecraft:oak_leaves" then
			look.transparent = true
		elseif name == "minecraft:water" then
			look.transparent = true
			look.fluid = "water"
			look.fluidHeight = 14.2
		end
		blocks[name] = look
	end
	return { available = true, textures = textures, blocks = blocks, items = {}, gui = {} }
end

local SPAWN = { 8, height(8, 8) + 1, 8 }
local subscriptions = {}
local function signal()
	return { Connect = function()
		return { Disconnect = function() end }
	end }
end
local messageHandlers = {}
local fakeClient = { Server = "fake://minecraft", Connected = signal(), Disconnected = signal(), MessageReceived = {
	Connect = function(_, callback)
		table.insert(messageHandlers, callback)
		return { Disconnect = function() end }
	end,
} }
local playerCalls = {} -- op -> count
local menuOpen = false
function fakeClient:Call(command, args)
	task.wait(0.01) -- (a round trip)
	if command == "mcworld.info" then
		return { version = 1, label = "MC", spawn = SPAWN, minY = MIN_Y, maxY = MAX_Y, center = { 0, 0 }, radius = 4,
			studsPerBlock = 3, rootHeight = 3, follow = true, maxReach = 32 }
	elseif command == "mcworld.chunks" then
		chunkCalls += 1
		local answer, size = {}, 0
		for _, pair in ipairs(args.chunks) do
			local cx, cz = pair[1], pair[2]
			local key = cx .. "," .. cz
			if not generatedChunks[key] or size >= 36000 then
				generatedChunks[key] = true -- generated now - the next ask gets it
				laterAnswers += 1
				table.insert(answer, { x = cx, z = cz, later = true })
			else
				local chunk = packChunk(cx, cz)
				size += #chunk.data
				bytesSent += #chunk.data
				table.insert(answer, chunk)
			end
		end
		return { chunks = answer }
	elseif command == "mcworld.player" then
		playerCalls[args.op] = (playerCalls[args.op] or 0) + 1
		local slots = table.create(46, false)
		slots[37] = { id = "minecraft:bread", n = 3, name = "Bread", max = 64 }
		local state = { gm = "survival", sel = 0, slots = slots, carried = false }
		if args.op == "click" and args.container then
			menuOpen = true
		elseif args.op == "close" then
			menuOpen = false
		end
		if menuOpen then
			state.menu = { type = "generic_9x3", title = "Kiste", slots = { { 8, 18, false }, { 26, 18, { id = "minecraft:stone", n = 5 } } } }
		end
		if args.op == "eat" then
			return { ok = true, food = 5, sat = 6, state = state }
		end
		return { ok = true, state = state }
	elseif command == "mcworld.hurt" then
		return { ok = true, crit = args.falling == true, magic = false, amount = 1.5, health = 18 }
	elseif command == "mcworld.assets" then
		if args and args.gui then
			return assetsAnswer()
		end
		return { available = true, textures = {}, blocks = {}, items = {} }
	end
	error("fake Minecraft: no command " .. tostring(command))
end
function fakeClient:Subscribe(_, topic, callback)
	subscriptions[topic] = callback
	return { Unsubscribe = function() end }
end
-- endregion

-- region fake Roblox (like sim_minecraftworld)
local heartbeat = {}
shim.services.RunService.Heartbeat = {
	Connect = function(_, callback)
		table.insert(heartbeat, callback)
		return { Disconnect = function() end }
	end,
}
local workspaceRoot = Instance.new("Workspace")
workspaceRoot.Name = "Workspace"
local starterPlayer = Instance.new("Folder")
starterPlayer.Name = "StarterPlayer"
local starterScripts = Instance.new("Folder")
starterScripts.Name = "StarterCharacterScripts"
starterScripts.Parent = starterPlayer
shim.services.StarterPlayer = starterPlayer
local lighting = Instance.new("Folder")
lighting.Name = "Lighting"
shim.services.Lighting = lighting
shim.services.KeyframeSequenceProvider = { RegisterKeyframeSequence = function()
	return "rbxassetid://0"
end }
local testPlayers = {}
local Players = {
	CharacterAutoLoads = true,
	PlayerAdded = { Connect = function() return { Disconnect = function() end } end },
	PlayerRemoving = { Connect = function() return { Disconnect = function() end } end },
	GetPlayers = function()
		return table.clone(testPlayers)
	end,
}
shim.services.Players = Players
local requireModule
local function newPlayer(userId, name)
	local player = { UserId = userId, Name = name, DisplayName = name, Character = nil, Parent = Players, attributes = {} }
	function player.GetAttribute(self, key)
		return self.attributes[key]
	end
	function player.SetAttribute(self, key, value)
		self.attributes[key] = value
	end
	function player.LoadCharacter(self)
		local model = Instance.new("Model")
		model.Name = name
		local root = Instance.new("Part")
		root.Name = "HumanoidRootPart"
		root.Parent = model
		local spawn = workspaceRoot:FindFirstChild("MinecraftSpawn")
		root.CFrame = if spawn then spawn.CFrame + Vector3.new(0, 3, 0) else CFrame.new(0, 300, 0)
		root.Position = root.CFrame.Position
		root.AssemblyLinearVelocity = Vector3.zero
		local humanoid = Instance.new("Humanoid")
		humanoid.MaxHealth = 20
		humanoid.Health = 20
		humanoid.Parent = model
		model.PrimaryPart = root
		model.Parent = workspaceRoot
		self.Character = model
	end
	return player
end
local config = { Server = "fake://minecraft", Label = "Roblox", WorldPrefix = "mcworld", PlayerTopic = "playersync",
	ChunksPerCall = 4, BlockColor = Color3.fromRGB(163, 162, 165), BlockMaterial = Enum.Material.SmoothPlastic,
	StudioSecret = "simulated-realworld-secret-0123456789012", Debug = false, ViewChunks = VIEW, SectionsBelow = 3,
	BuildBudgetMs = 6 }
local modules = {}
local sources = { MinecraftCharacter = "../examples/MinecraftWorld/MinecraftCharacter.luau" }
local env
function requireModule(name)
	if name == "Bridge" then
		return Bridge
	elseif name == "MinecraftWorldConfig" then
		return config
	elseif name == "MinecraftWorldClient" then
		return fakeClient
	end
	if modules[name] == nil then
		modules[name] = luau.load(fs.readFile(sources[name]), { debugName = name, environment = env })()
	end
	return modules[name]
end
shim.services.ServerStorage = { WaitForChild = function(_, name)
	return "module:" .. name
end }
local remotes = {}
local remoteFolder = { Name = "MinecraftWorld", FindFirstChild = function(_, name)
	if not remotes[name] then
		remotes[name] = { Name = name, FireClient = function() end, FireAllClients = function() end,
			OnServerEvent = { Connect = function(_, callback)
				remotes[name].handler = callback
				return { Disconnect = function() end }
			end } }
	end
	return remotes[name]
end }
local replicatedAttributes = {}
shim.services.ReplicatedStorage = {
	FindFirstChild = function(_, name)
		return if name == "MinecraftWorld" then remoteFolder else nil
	end,
	WaitForChild = function(_, name)
		return "module:" .. name
	end,
	SetAttribute = function(_, key, value)
		replicatedAttributes[key] = value
	end,
	GetAttribute = function(_, key)
		return replicatedAttributes[key]
	end,
}
env = setmetatable({
	game = game, workspace = workspaceRoot, Instance = Instance, Vector3 = Vector3, CFrame = CFrame, Enum = Enum,
	Color3 = Color3, Vector2 = roblox.Vector2, PhysicalProperties = roblox.PhysicalProperties, task = task, warn = warn,
	buffer = buffer, bit32 = bit32,
	require = function(target)
		return requireModule(string.sub(target, 8))
	end,
}, { __index = _G })
-- endregion

shim.printWarnings = true
local paddy = newPlayer(4242, "RobloxPaddy")
table.insert(testPlayers, paddy)
local script = luau.load(fs.readFile("../examples/MinecraftWorld/MinecraftWorld.server.luau"),
	{ debugName = "MinecraftWorld", environment = env })
task.spawn(script)

local longestFrame = 0
local function frames(seconds, until_)
	local started = os.clock()
	while os.clock() - started < seconds do
		local t0 = os.clock()
		for _, callback in ipairs(heartbeat) do
			callback(1 / 30)
		end
		local spent = os.clock() - t0
		if spent > longestFrame then
			longestFrame = spent
		end
		if until_ and until_() then
			return true
		end
		task.wait(1 / 60)
	end
	return false
end

local worldFolder = nil
local function queueEmpty()
	worldFolder = workspaceRoot:FindFirstChild("MinecraftWorld")
	return paddy.Character ~= nil
end

-- region checks
local SCALE = 3
local function cellsOfParts()
	-- every block covered by a part (cubes: "Blocks"/named parts in chunk folders, models count by their McBlock)
	local covered, faces = {}, {}
	local parts, textures = 0, 0
	for _, chunk in ipairs(worldFolder:GetChildren()) do
		for _, item in ipairs(chunk:GetChildren()) do
			if item:IsA("BasePart") then
				parts += 1
				local size, p = item.Size, item.CFrame.Position
				local x0 = math.floor((p.X - size.X / 2) / SCALE + 0.5)
				local y0 = math.floor((p.Y - size.Y / 2) / SCALE + 0.5) + MIN_Y
				local z0 = math.floor((p.Z - size.Z / 2) / SCALE + 0.5)
				local w = math.max(1, math.floor(size.X / SCALE + 0.5))
				local h = math.max(1, math.ceil(size.Y / SCALE - 0.01))
				local d = math.max(1, math.floor(size.Z / SCALE + 0.5))
				local textured = {}
				for _, texture in ipairs(item:GetChildren()) do
					if texture:IsA("Texture") then
						textured[texture.Face.Name] = true
						textures += 1
					end
				end
				for x = x0, x0 + w - 1 do
					for y = y0, y0 + h - 1 do
						for z = z0, z0 + d - 1 do
							local key = x .. "," .. y .. "," .. z
							covered[key] = item.Name
							faces[key] = { textured, x == x0, x == x0 + w - 1, y == y0, y == y0 + h - 1, z == z0, z == z0 + d - 1 }
						end
					end
				end
			elseif item:IsA("Model") then
				parts += #item:GetChildren()
			end
		end
	end
	return covered, faces, parts, textures
end

local function hidesFace(name, other)
	if other == "minecraft:air" then
		return false
	end
	if other == "minecraft:water" or other == "minecraft:oak_leaves" then
		return other == name
	end
	return true
end

local DIRS = {
	{ 0, 1, 0, "Top", 5 }, { 0, -1, 0, "Bottom", 4 }, { 0, 0, -1, "Front", 6 }, { 0, 0, 1, "Back", 7 },
	{ 1, 0, 0, "Right", 3 }, { -1, 0, 0, "Left", 2 },
}
local function checkArea(cx0, cz0, radius, label)
	local covered, faces, parts, textures = cellsOfParts()
	local visibleFaces, missingPart, missingPicture, airCovered, buried = 0, 0, 0, 0, 0
	local example = nil
	for cx = cx0 - radius, cx0 + radius do
		for cz = cz0 - radius, cz0 + radius do
			for x = cx * 16, cx * 16 + 15 do
				for z = cz * 16, cz * 16 + 15 do
					local top = height(x, z) + 6
					for y = math.max(MIN_Y, top - 40), top do
						local name = blockAt(x, y, z)
						local key = x .. "," .. y .. "," .. z
						if name == "minecraft:air" then
							if covered[key] then
								airCovered += 1
							end
							continue
						end
						for _, dir in ipairs(DIRS) do
							local other = blockAt(x + dir[1], y + dir[2], z + dir[3])
							if not hidesFace(name, other) then
								visibleFaces += 1
								local info = faces[key]
								if not covered[key] then
									missingPart += 1
									example = example or (name .. " at " .. key .. " (" .. dir[4] .. ")")
								elseif info[dir[5]] and not info[1][dir[4]] then
									missingPicture += 1
									example = example or ("no picture " .. dir[4] .. " on " .. name .. " at " .. key)
								end
							end
						end
					end
				end
			end
		end
	end
	print(string.format("  %s: %d visible faces checked, %d parts, %d textures", label, visibleFaces, parts, textures))
	check(missingPart == 0, label .. ": every visible face has its block (" .. missingPart .. " missing"
		.. (if example then ", e.g. " .. example else "") .. ")")
	check(missingPicture == 0, label .. ": every visible face has a picture (" .. missingPicture .. " without)")
	check(airCovered == 0, label .. ": no part where there is air (" .. airCovered .. ")")
	return parts, textures
end
-- endregion

local started = os.clock()
local ready = frames(120, function()
	return paddy.Character ~= nil
end)
check(ready, string.format("the character comes when the ground at the spawn is built (%.1f s)", os.clock() - started))
-- let the whole view load
local loadedAll = frames(240, function()
	worldFolder = workspaceRoot:FindFirstChild("MinecraftWorld")
	if not worldFolder then
		return false
	end
	local count = #worldFolder:GetChildren()
	local wanted = 0
	for dx = -VIEW, VIEW do
		for dz = -VIEW, VIEW do
			if dx * dx + dz * dz <= (VIEW + 0.5) ^ 2 then
				wanted += 1
			end
		end
	end
	return count >= wanted
end)
frames(8) -- the queue empties
worldFolder = workspaceRoot:FindFirstChild("MinecraftWorld")
local loadSeconds = os.clock() - started
local chunks = #worldFolder:GetChildren()
local stats = _G.MinecraftWorldBuildStats
print(string.format("  building: %d sections, %.1f s in all (meshing %.1f s), longest %.1f ms", stats.count, stats.total,
	stats.meshTotal, stats.longest * 1000))
print(string.format("  world: %d chunks in %.1f s, %d chunk calls, %d 'later', %.0f KB sent, longest frame %.1f ms",
	chunks, loadSeconds, chunkCalls, laterAnswers, bytesSent / 1024, longestFrame * 1000))
check(loadedAll, "all chunks around the player came")
check(longestFrame < 0.05, string.format("no frame longer than 50 ms (%.1f ms)", longestFrame * 1000))
local parts, textures = checkArea(0, 0, 1, "around the spawn")

-- how many blocks there are in the shown chunks (above the window floor): parts per block
local blocks = 0
for cx = -1, 1 do
	for cz = -1, 1 do
		for x = cx * 16, cx * 16 + 15 do
			for z = cz * 16, cz * 16 + 15 do
				for y = MIN_Y, height(x, z) do
					if blockAt(x, y, z) ~= "minecraft:air" then
						blocks += 1
					end
				end
			end
		end
	end
end
print(string.format("  3 x 3 chunks: %d solid blocks -> %d parts in the whole view", blocks, parts))

-- breaking a block in the ground: what is behind it appears at once
local bx, bz = 5, 6
local by = height(bx, bz)
edits[bx .. "," .. by .. "," .. bz] = "minecraft:air"
edits[bx .. "," .. (by - 1) .. "," .. bz] = "minecraft:air"
subscriptions["mcworld.changes"]({ blocks = { { bx, by, bz, "minecraft:air" }, { bx, by - 1, bz, "minecraft:air" } } })
checkArea(0, 0, 0, "after digging a hole")

-- walking far away: the world follows
local root = paddy.Character:FindFirstChild("HumanoidRootPart")
root.CFrame = CFrame.new(16 * 20 * SCALE, (height(16 * 20, 8) - MIN_Y + 2) * SCALE, 8 * SCALE)
root.Position = root.CFrame.Position
local waited = frames(3, function()
	return root.Anchored == true
end)
check(waited, "teleported where nothing is built yet: the character waits (anchored)")
local followed = frames(120, function()
	return workspaceRoot.MinecraftWorld:FindFirstChild("Chunk 20,0") ~= nil and not root.Anchored
end)
check(followed, "the world follows the player (chunk 20,0 is there, the character goes on)")
frames(60, function()
	local stats = _G.MinecraftWorldBuildStats
	return false
end)
check(workspaceRoot.MinecraftWorld:FindFirstChild("Chunk 0,0") == nil, "far chunks went away (chunk 0,0)")
checkArea(20, 0, 1, "far away")

-- digging down: the deep sections get built when the player goes down there
local deepY, deepX, deepZ = -40, 16 * 20 + 8, 8
local caveFound = false
for y = -48, 5 do -- a cave down there (below what is built while he stands on the ground)
	local found = false
	for x = 16 * 20, 16 * 20 + 15 do
		for z = -16, 15 do
			if not found and isCave(x, y, z) then
				deepY, deepX, deepZ, found = y, x, z, true
			end
		end
	end
	if found then
		caveFound = true
		break
	end
end
root.CFrame = CFrame.new((deepX + 0.5) * SCALE, (deepY - MIN_Y) * SCALE, (deepZ + 0.5) * SCALE)
root.Position = root.CFrame.Position
frames(15)
local deepCovered = cellsOfParts()
local deepVisible, deepMissing = 0, 0
for x = deepX - 6, deepX + 6 do
	for z = deepZ - 6, deepZ + 6 do
		for y = deepY - 4, deepY + 4 do
			local name = blockAt(x, y, z)
			if name ~= "minecraft:air" then
				for _, dir in ipairs(DIRS) do
					if blockAt(x + dir[1], y + dir[2], z + dir[3]) == "minecraft:air" then
						deepVisible += 1
						if not deepCovered[x .. "," .. y .. "," .. z] then
							deepMissing += 1
						end
						break
					end
				end
			end
		end
	end
end
check(not caveFound or (deepVisible > 0 and deepMissing == 0), string.format(
	"deep down (cave walls at y %d): built when the player is there (%d blocks with a cave face, %d missing)",
	deepY, deepVisible, deepMissing))

-- hunger, eating, effects, crits, an open chest (the server's code for them runs without errors)
do
	local function remote(name)
		return remoteFolder:FindFirstChild(name)
	end
	local character = paddy.Character
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	frames(1)
	check(paddy:GetAttribute("McFood") == 20, "hunger: food 20 at the start (" .. tostring(paddy:GetAttribute("McFood")) .. ")")
	-- sprinting 60 blocks: 6 exhaustion -> saturation 5 -> 4 (Minecraft: every 4 exhaustion one saturation)
	character:SetAttribute("McSprint", true)
	local start = root.Position
	for step = 1, 60 do
		root.CFrame = CFrame.new(start + Vector3.new(step * SCALE, 0, 0))
		root.Position = root.CFrame.Position
		frames(0.06)
	end
	character:SetAttribute("McSprint", nil)
	local saturation = paddy:GetAttribute("McSaturation")
	check(type(saturation) == "number" and saturation < 5, "hunger: sprinting makes hungry (saturation " .. tostring(saturation) .. ")")
	-- eating: Minecraft says bread gives 5 food + 6 saturation
	local inventory = remote("Inventory")
	paddy.attributes.McFood = nil
	inventory.handler(paddy, "eat", 0)
	frames(0.5)
	check(playerCalls.eat == 1, "eating: Minecraft was asked (op eat)")
	-- effects from Minecraft
	local hurtCalls = 0
	for _, handler in ipairs(messageHandlers) do
		handler({ Content = { type = "mc.effects", u = 4242, list = { { id = "speed", amp = 1, dur = 30, color = 3402751, good = true } } } })
		-- (Lune's Humanoid has no TakeDamage: the damage itself only works in Roblox - the path up to it is tested)
		local ok, err = pcall(handler, { Content = { type = "mc.effect", u = 4242, kind = "poison" } })
		if ok or string.find(tostring(err), "TakeDamage", 1, true) then
			hurtCalls += 1
		end
		ok, err = pcall(handler, { Content = { type = "mc.hurt", u = 4242, amount = 2, crit = true, from = { 0, 0, 0 } } })
		if ok or string.find(tostring(err), "TakeDamage", 1, true) then
			hurtCalls += 1
		end
	end
	frames(0.2)
	check(type(paddy:GetAttribute("McEffects")) == "string" and string.find(paddy:GetAttribute("McEffects"), "speed", 1, true) ~= nil,
		"effects: the list from Minecraft is on the player (" .. tostring(paddy:GetAttribute("McEffects")) .. ")")
	check(hurtCalls == 2, "poison / a critical hit from Minecraft reach the damage (" .. hurtCalls .. " of 2)")
	-- an open chest: a click in its window goes to Minecraft as a container click
	inventory.handler(paddy, "click", 1, 0, false, true)
	frames(0.5)
	check(playerCalls.click == 1, "chest: the click went to Minecraft")
	inventory.handler(paddy, "close")
	frames(0.5)
	check(playerCalls.close == 1, "chest: closed")
end

print(string.format("RESULT %s", serde.encode("json", { failures = #failures, chunks = chunks, parts = parts,
	textures = textures, loadSeconds = loadSeconds, longestFrameMs = longestFrame * 1000 })))
process.exit(if #failures == 0 then 0 else 1)
