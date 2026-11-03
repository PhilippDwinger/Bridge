--!native
-- (Luau native code: the meshing of thousands of sections in real worlds runs much faster)
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
	 10. day, night, weather (topic mcworld.sky): Minecraft's own sky values (time, sun / moon, colours, light, rain /
	     snow) as attributes of Lighting ("Mc..."), the clients draw the sky like Minecraft (MinecraftSky); water and
	     lava as high as in Minecraft (McFluid on their parts: the clients swim / lose air there), Drown = air is out

	Needs in ServerStorage: Bridge, MinecraftWorldConfig, MinecraftWorldClient (shared Bridge client), PlayerSyncConfig.
]]
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
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
local SKY = Config.WorldPrefix .. ".sky"
local MOBS = Config.WorldPrefix .. ".mobs"
local MOB = Config.WorldPrefix .. ".mob"
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
	loadStarted = 0, -- os.clock() of the last (re)load
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
local drownRemote = remote("RemoteEvent", "Drown") -- client: the air under water is out (Minecraft: 2 damage)
-- server -> clients: (kind, position, extra) Minecraft's particles: "crit", "magic", "effect" (colour), "smoke" ...
local particlesRemote = remote("RemoteEvent", "Particles")
local titleRemote = remote("RemoteEvent", "Title") -- server -> client: Minecraft's title / subtitle / action bar for him
local lastSwing = {} -- player -> os.clock() of his last swing (Minecraft: every swing starts the attack charge again)
local hunger = {} -- player -> {food, sat, exhaustion, timer, peaceful, last, rising} (region hunger)
local hungerOf, showHunger -- below (region hunger)

local function log(...)
	print("[MinecraftWorld]", ...)
end

-- A chunk: "x,z" in the overworld, "x,z@d" in dimension d (Nether 1, End 2 ...)
local function chunkKey(x, z, d)
	if d and d ~= 0 then
		return x .. "," .. z .. "@" .. d
	end
	return x .. "," .. z
end

-- region dimensions: every Minecraft dimension lies at its own height in this one world (Minecraft y + shift, the mod
-- sends Roblox y everywhere): overworld 0, the Nether 1024, the End 2048 (info.dims)
local dimAt, dimInfo, insideWorld
do
	local DIM_BAND = 1024
	local DIM_BELOW = 352
	function dimAt(blockY)
		local dims = world.info and world.info.dims
		if type(dims) ~= "table" or #dims == 0 then
			return 0
		end
		return math.clamp((math.floor(blockY) + DIM_BELOW) // DIM_BAND, 0, #dims - 1)
	end
	-- {i, kind, shift, minY, maxY} of a dimension (minY / maxY: Roblox y)
	function dimInfo(d)
		local info = world.info
		local dims = info and info.dims
		local entry = type(dims) == "table" and dims[(d or 0) + 1]
		if type(entry) == "table" then
			local shift = tonumber(entry.shift) or 0
			return {
				i = d,
				kind = entry.kind or "overworld",
				shift = shift,
				minY = (tonumber(entry.minY) or 0) + shift,
				maxY = (tonumber(entry.maxY) or 256) + shift,
				ceiling = entry.ceiling == true,
			}
		end
		return { i = 0, kind = "overworld", shift = 0, minY = info and info.minY or -64, maxY = info and info.maxY or 320, ceiling = false }
	end
	-- Is a block y inside its dimension (not in the gap between two)?
	function insideWorld(blockY)
		local dim = dimInfo(dimAt(blockY))
		return blockY >= dim.minY and blockY < dim.maxY
	end
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

-- region sign text (from Minecraft's sign block entities: [x, y, z, front lines, back lines, front colour, back colour,
-- glowing front, glowing back]): on the board (the biggest piece of the sign's model) like Minecraft writes it
local setSignText
do
	local SIGN_FACES = { Enum.NormalId.Front, Enum.NormalId.Back, Enum.NormalId.Left, Enum.NormalId.Right, Enum.NormalId.Top,
		Enum.NormalId.Bottom }
	local SIGN_FACING = { north = Vector3.new(0, 0, -1), south = Vector3.new(0, 0, 1), east = Vector3.new(1, 0, 0),
		west = Vector3.new(-1, 0, 0) }
	local function signFront(name)
		local rotation = tonumber(string.match(name, "rotation=(%d+)"))
		if rotation then
			local a = math.rad(rotation * 22.5) -- (Minecraft: 0 = facing south, 4 = west ...)
			return Vector3.new(-math.sin(a), 0, math.cos(a))
		end
		return SIGN_FACING[string.match(name, "facing=(%a+)") or "south"] or Vector3.new(0, 0, 1)
	end
	local function rgbOf(value, fallback)
		local n = tonumber(value)
		if not n then
			return fallback
		end
		return Color3.fromRGB(bit32.band(bit32.rshift(n, 16), 255), bit32.band(bit32.rshift(n, 8), 255), bit32.band(n, 255))
	end
	function setSignText(model, sign)
		for _, old in ipairs(model:GetDescendants()) do
			if old:IsA("SurfaceGui") and old.Name == "McSignText" then
				old:Destroy()
			end
		end
		local board, best = nil, 0
		for _, piece in ipairs(model:GetChildren()) do
			if piece:IsA("BasePart") and piece.Name == "Piece" then
				local size = piece.Size
				local area = math.max(size.X * size.Y, size.Y * size.Z, size.X * size.Z)
				if area > best then
					board, best = piece, area
				end
			end
		end
		if not board or type(sign) ~= "table" then
			return
		end
		local front = signFront(model.Name)
		for side = 1, 2 do
			local lines = sign[3 + side]
			local any = false
			for _, line in ipairs(if type(lines) == "table" then lines else {}) do
				if type(line) == "string" and line ~= "" then
					any = true
				end
			end
			if not any then
				continue
			end
			local want = if side == 1 then front else -front
			local face, best2 = Enum.NormalId.Front, -2
			for _, normal in ipairs(SIGN_FACES) do
				local d = board.CFrame:VectorToWorldSpace(Vector3.FromNormalId(normal)):Dot(want)
				if d > best2 then
					face, best2 = normal, d
				end
			end
			local glow = sign[7 + side] == true
			local color = rgbOf(sign[5 + side], Color3.new(0, 0, 0))
			local gui = Instance.new("SurfaceGui")
			gui.Name = "McSignText"
			gui.Face = face
			gui.SizingMode = Enum.SurfaceGuiSizingMode.PixelsPerStud
			gui.PixelsPerStud = 60
			gui.LightInfluence = if glow then 0 else 1
			gui.MaxDistance = 60
			for i = 1, 4 do
				local label = Instance.new("TextLabel")
				label.BackgroundTransparency = 1
				label.Size = UDim2.fromScale(0.96, 0.21)
				label.Position = UDim2.fromScale(0.02, 0.08 + (i - 1) * 0.215)
				label.Font = Enum.Font.Arcade
				label.TextScaled = true
				label.Text = tostring(lines[i] or "")
				label.TextColor3 = if glow and color == Color3.new(0, 0, 0) then Color3.fromRGB(240, 235, 200) else color
				label.TextStrokeTransparency = if glow then 0.2 else 1
				label.TextStrokeColor3 = Color3.new(color.R * 0.4, color.G * 0.4, color.B * 0.4)
				label.Parent = gui
			end
			gui.Parent = board
		end
	end
end

-- endregion

local function cellIndex(x, y, z) -- 1-based, order y, z, x (as the mod sends it)
	return y * 256 + z * 16 + x + 1
end

-- The blocks of a section: 4096 palette indices (u16) in a buffer - 8 KB instead of a 64 KB table per section, so
-- real worlds (hundreds of chunks, 24 sections high) fit into the server's memory
local function newCells()
	return buffer.create(8192) -- (all 0 = air)
end
local function cellAt(cells: buffer, i: number): number
	return buffer.readu16(cells, i * 2 - 2)
end
local function setCell(cells: buffer, i: number, value: number)
	buffer.writeu16(cells, i * 2 - 2, value)
end

local queueSection -- below (sections wait to be built, nearest first)
local buildStats = { count = 0, total = 0, longest = 0, meshTotal = 0 } -- (shown by /welt)
local TOP = "|top" -- the top of water / lava: lower than a block (Minecraft: amount / 9) - see fluidTop

-- Water / lava with no same fluid above: its own key (the part is lower, like Minecraft's fluid surface)
local function fluidTop(section, above, i, key)
	local look = world.assets and world.assets.blocks[key]
	if not look or not look.fluid then
		return key
	end
	local aboveName
	if i + 256 <= 4096 then
		aboveName = section.palette[cellAt(section.cells, i + 256) + 1]
	elseif above then
		aboveName = above.palette[cellAt(above.cells, i + 256 - 4096) + 1]
	end
	local aboveLook = aboveName and world.assets.blocks[aboveName]
	if aboveLook and aboveLook.fluid == look.fluid then
		return key -- (water above: full height)
	end
	return key .. TOP
end

--[[
	Culling (like Minecraft: only faces you can see are drawn). Per palette entry of a section:
	  occ = a full, not see-through cube (stone, dirt, planks - and the grey placeholder until its look comes): hides
	        the face of whatever touches it
	  grp = glass / leaves / water hide the faces between blocks of their own kind (Minecraft does the same)
	A block whose six neighbours all hide it is not built at all ("buried": the inside of the ground), its faces get no
	pictures; buried full cubes may even become part of a neighbour's box (bigger boxes = fewer parts) - nobody can see
	them anyway, and they collide the same. A chunk that is not loaded yet counts as solid (no wall at the edge of the
	world); when it comes, the faces toward it are looked at again.
]]
local BITS = { up = 1, down = 2, north = 4, south = 8, east = 16, west = 32 }

local function classify(section)
	local occ, grp, keys = {}, {}, {}
	local assets = world.assets
	for p, name in ipairs(section.palette) do
		local key = renderKey(name)
		keys[p] = key or false
		if key == nil then
			occ[p] = false
			grp[p] = false
		elseif key == "placeholder" then
			occ[p] = true
			grp[p] = false
		else
			local look = assets and assets.blocks[key]
			if look and look.cube == true then
				if look.fluid then
					occ[p] = false
					grp[p] = "fluid:" .. tostring(look.fluid)
				elseif look.transparent then
					occ[p] = false
					grp[p] = key -- glass next to glass, leaves next to the same leaves: that face is not drawn
				else
					occ[p] = true
					grp[p] = false
				end
			else
				occ[p] = false -- models (stairs, torches, fences ...) never hide anything
				grp[p] = false
			end
		end
	end
	return occ, grp, keys
end

-- The six neighbour sections: a section (table), nil (air: above the top, or no blocks there) or false (solid:
-- below the bottom of the world, or a chunk that is not loaded)
local function neighbourSections(chunk, sectionY)
	local dim = dimInfo(chunk.dim)
	local minSection = dim.minY // 16
	local maxSection = (dim.maxY - 1) // 16
	local function side(dx, dz)
		local other = world.chunks[chunkKey(chunk.x + dx, chunk.z + dz, chunk.dim)]
		if not other then
			return false
		end
		return other.sections[sectionY]
	end
	local up = if sectionY + 1 > maxSection then nil else chunk.sections[sectionY + 1]
	local down = if sectionY - 1 < minSection then false else chunk.sections[sectionY - 1]
	return up, down, side(0, -1), side(0, 1), side(1, 0), side(-1, 0)
end

--- Greedy meshing of one 16x16x16 section with culling: boxes {x, y, z, w, h, d, key, faces} of blocks with the same
--- look (faces = bits of the sides that can be seen somewhere: only those get pictures).
local function meshSection(chunk, sectionY, section)
	local cells = section.cells
	local occ, grp, pkeys = classify(section)
	local up, down, north, south, east, west = neighbourSections(chunk, sectionY)
	local neighbour = {}
	for name, other in pairs({ up = up, down = down, north = north, south = south, east = east, west = west }) do
		if other then
			local o, g = classify(other)
			neighbour[name] = { other.cells, o, g }
		end
	end
	local nUp, nDown, nNorth, nSouth, nEast, nWest = neighbour.up, neighbour.down, neighbour.north, neighbour.south,
		neighbour.east, neighbour.west
	-- Does the block at index i of the section (s = {cells, occ, grp}, false = solid, nil = air) hide a face of
	-- a block of group own?
	local function hides(s, i, own)
		local q = cellAt(s[1], i) + 1
		return s[2][q] or (own and s[3][q] == own)
	end
	local keys = table.create(4096, false) -- render key of every block that is built (false: air / buried)
	local wild = table.create(4096, false) -- buried full cubes: may go into any neighbouring full-cube box
	local masks = table.create(4096, 0)
	local waits = nil
	local here = { cells, occ, grp }
	for i = 1, 4096 do
		local p = cellAt(cells, i) + 1
		local key = pkeys[p]
		if not key then
			continue
		end
		local own = grp[p]
		local n = i - 1
		local x, z, y = n % 16, (n // 16) % 16, n // 256
		local mask = 0
		-- up / down
		if y < 15 then
			if not hides(here, i + 256, own) then mask += 1 end
		elseif up == nil then
			mask += 1
		elseif nUp and not hides(nUp, i - 3840, own) then
			mask += 1
		end
		if y > 0 then
			if not hides(here, i - 256, own) then mask += 2 end
		elseif down == nil then
			mask += 2
		elseif nDown and not hides(nDown, i + 3840, own) then
			mask += 2
		end
		-- north (-z) / south (+z)
		if z > 0 then
			if not hides(here, i - 16, own) then mask += 4 end
		elseif north == nil then
			mask += 4
		elseif north == false then
			waits = waits or {}
			waits.north = true
		elseif not hides(nNorth, i + 240, own) then
			mask += 4
		end
		if z < 15 then
			if not hides(here, i + 16, own) then mask += 8 end
		elseif south == nil then
			mask += 8
		elseif south == false then
			waits = waits or {}
			waits.south = true
		elseif not hides(nSouth, i - 240, own) then
			mask += 8
		end
		-- east (+x) / west (-x)
		if x < 15 then
			if not hides(here, i + 1, own) then mask += 16 end
		elseif east == nil then
			mask += 16
		elseif east == false then
			waits = waits or {}
			waits.east = true
		elseif not hides(nEast, i - 15, own) then
			mask += 16
		end
		if x > 0 then
			if not hides(here, i - 1, own) then mask += 32 end
		elseif west == nil then
			mask += 32
		elseif west == false then
			waits = waits or {}
			waits.west = true
		elseif not hides(nWest, i + 15, own) then
			mask += 32
		end
		if mask == 0 and occ[p] then
			wild[i] = true -- buried: not built (unless a neighbouring box takes it)
		else
			keys[i] = if key ~= "placeholder" then fluidTop(section, up or nil, i, key) else key
			masks[i] = mask
		end
	end
	section.waits = waits
	local done = {}
	local boxes = {}
	for y = 0, 15 do
		for z = 0, 15 do
			for x = 0, 15 do
				local start = cellIndex(x, y, z)
				local key = keys[start]
				if key and not done[start] then
					local single = standsAlone(key) -- a model (lever, stairs, ...) or a cube with its own collision: never merged
					local solid = not single and occ[cellAt(cells, start) + 1] == true
					local function same(cx, cy, cz)
						if single then
							return false
						end
						local i = cellIndex(cx, cy, cz)
						if done[i] then
							return false
						end
						return keys[i] == key or (solid and wild[i])
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
					local faces = 0
					for dy = 0, h - 1 do
						for dz = 0, d - 1 do
							for dx = 0, w - 1 do
								local i = cellIndex(x + dx, y + dy, z + dz)
								done[i] = true
								faces = bit32.bor(faces, masks[i])
							end
						end
					end
					table.insert(boxes, { x = x, y = y, z = z, w = w, h = h, d = d, key = key, faces = faces })
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
	return string.format("%s|%d|%d|%d|%d|%d|%d|%d", box.key, box.x, box.y, box.z, box.w, box.h, box.d, box.faces or 63)
end

-- Light like Minecraft's block light (torch 14, glowstone / lava 15): a PointLight reaching that many blocks,
-- in the warm colour of Minecraft's block light
local function addLight(part, light, scale)
	if type(light) ~= "number" or light <= 0 then
		return
	end
	local point = Instance.new("PointLight")
	point.Name = "McLight"
	point.Range = math.min(60, light * scale)
	point.Brightness = 0.6 + light / 15 * 1.2
	point.Color = Color3.fromRGB(255, 216, 140) -- Minecraft: block_light_tint #FFD88C
	point.Shadows = true
	point.Parent = part
end

local function renderSection(chunk, sectionY, section, force)
	local old = section.parts
	local kept = {}
	local scale = world.info.studsPerBlock
	local minY = world.info.minY
	local meshStarted = os.clock()
	local boxes = meshSection(chunk, sectionY, section)
	buildStats.meshTotal += os.clock() - meshStarted
	for _, box in ipairs(boxes) do
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
		local top = string.sub(box.key, -#TOP) == TOP
		local name = if top then string.sub(box.key, 1, -#TOP - 1) else box.key
		local look = world.assets and world.assets.blocks[name]
		local corner = Vector3.new(blockX * scale, (blockY - minY) * scale, blockZ * scale)
		if look and look.cube ~= true then
			local model = buildModel(name, look, corner, scale, Vector3.new(blockX, blockY, blockZ))
			local sign = chunk.signs and chunk.signs[blockX .. "," .. blockY .. "," .. blockZ]
			if sign then
				setSignText(model, sign)
			end
			if look.light then
				for _, piece in ipairs(model:GetChildren()) do
					if piece:IsA("BasePart") then
						addLight(piece, look.light, scale) -- (one light per block, in its first part)
						break
					end
				end
			end
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
		-- the top of water / lava: Minecraft's height (8/9 of a block for a source, lower for flowing water)
		local height = box.h
		if top and look and type(look.fluidHeight) == "number" then
			height = box.h - 1 + math.clamp(look.fluidHeight / 16, 0.05, 1)
		end
		part.Size = Vector3.new(box.w * scale, height * scale, box.d * scale)
		part.CFrame = CFrame.new(
			(blockX + box.w / 2) * scale,
			(blockY - minY + height / 2) * scale,
			(blockZ + box.d / 2) * scale
		)
		if look then
			-- Textured cube: the colour shows until the client has made the pictures; one tile = one block.
			-- Glass / leaves: the part is invisible, only the pictures (with their holes) show.
			part.Name = name
			part.Color = Color3.fromRGB(look.color[1], look.color[2], look.color[3])
			if look.transparent then
				part.Transparency = 1
				part.CastShadow = false
			end
			if look.fluid then
				-- water / lava: see-through, you go through it, nobody aims at it; the clients find it by McFluid
				-- (swimming, air under water) - the part is as high as the fluid
				part.CanCollide = false
				part.CanQuery = false
				part.CanTouch = false
				part.CastShadow = false
				part:SetAttribute("McFluid", look.fluid)
			end
			for _, face in ipairs(FACES) do
				if bit32.band(box.faces or 63, BITS[face[2]]) == 0 then
					continue -- (a side nobody can see: no picture)
				end
				local key = look.faces[face[2]]
				local texture = world.assets.textures[key]
				local span = if texture and texture.span then texture.span else 1
				pictureOn(part, face[1], key, scale * span, scale * span)
			end
			addLight(part, look.light, scale)
			if look.boxes then
				-- a cube with its own collision (soul sand): the picture does not collide, its boxes do
				part.CanCollide = false
				part.CanQuery = look.outline == nil
				local holder = Instance.new("Model")
				holder.Name = name
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
	local cells = newCells()
	local count = 0
	local runs = data.runs or {}
	for i = 1, #runs - 1, 2 do
		local index, length = runs[i], runs[i + 1]
		if count + length > 4096 then
			error("section y=" .. tostring(data.y) .. " has more than 4096 blocks")
		end
		for _ = 1, length do
			count += 1
			setCell(cells, count, index)
		end
	end
	if count ~= 4096 then
		error("section y=" .. tostring(data.y) .. " has " .. count .. " blocks instead of 4096")
	end
	return { palette = data.palette or { "minecraft:air" }, cells = cells, parts = {} }
end

-- v 2 (packed, mod 20+): one palette for the chunk, the cells of all its sections in one zlib stream (Base64)
local function decodePacked(data)
	local raw = Bridge.Inflate(Bridge.Base64Decode(data.data))
	local wide = data.wide == true
	local size = if wide then 8192 else 4096
	local ys = data.ys or {}
	local source = buffer.fromstring(raw)
	if buffer.len(source) ~= size * #ys then
		error(string.format("packed chunk: %d bytes for %d sections", buffer.len(source), #ys))
	end
	local palette = data.palette or { "minecraft:air" }
	local sections = {}
	for n, sectionY in ipairs(ys) do
		local cells = newCells()
		local offset = (n - 1) * size
		if wide then
			buffer.copy(cells, 0, source, offset, 8192)
		else
			for i = 0, 4095 do
				buffer.writeu16(cells, i * 2, buffer.readu8(source, offset + i))
			end
		end
		-- (every section its own copy of the palette: blocks placed later add their names to it)
		sections[sectionY] = { palette = table.clone(palette), cells = cells, parts = {} }
	end
	return sections
end

--[[
	Building in portions: sections wait in a queue and are built nearest first, at most BuildBudgetMs per frame - a
	real world (thousands of sections) loads without the server ever standing still. Blocks placed / broken are built
	at once (applyBlocks), not queued.
	Vertical window: a section is only built if it is near the ground of its chunk (the lowest surface in the chunk,
	so cliffs and ravines are there) or not deeper than SectionsBelow below the lowest player - caves deep under
	everybody wait until somebody goes down there (they are inside the ground: nobody can see them).
]]
local VIEW = math.clamp(math.floor(tonumber(Config.ViewChunks) or 5), 1, 16)
local BELOW = math.max(0, math.floor(tonumber(Config.SectionsBelow) or 3))
local BUDGET = math.clamp(tonumber(Config.BuildBudgetMs) or 6, 1, 50) / 1000
local loader = {
	retryAt = {}, -- chunk key -> os.clock(): ask again from then on (Minecraft is still generating it)
	inFlight = {}, -- chunk key -> true: asked right now
	reload = {}, -- chunk key -> true: load again (many changes there)
	points = nil, -- where the players are: {cx, cz, sy} (the spawn while nobody is there)
	playerFloor = nil, -- lowest section that has to be built because of the players
	hasPlayers = false,
}
local renderQueue = {} -- {chunk, sy}: nearest at the end
local queueSorted = true
local queueSortedAt = 0

local function renderFromOf(chunk)
	local dim = dimInfo(chunk.dim)
	local ground = ((chunk.surface or dim.minY) - 8) // 16
	local floors = loader.playerFloor
	local floor = if type(floors) == "table" then floors[chunk.dim or 0] else nil
	if floor == nil then
		if (chunk.dim or 0) ~= 0 then
			return dim.minY // 16 -- (nobody of this dimension known yet: all of it)
		end
		local spawn = world.info.spawn
		floor = spawn[2] // 16 - BELOW
	end
	if dim.ceiling then
		return floor -- (the Nether: its "surface" is the bedrock roof - from below the players up)
	end
	return math.min(ground, floor)
end

local function buildSection(chunk, sectionY, section, force)
	if sectionY < (chunk.renderFrom or -math.huge) then
		for _, part in pairs(section.parts) do
			part:Destroy()
		end
		section.parts = {}
		section.built = false
		return
	end
	renderSection(chunk, sectionY, section, force)
	section.built = true
end

queueSection = function(chunk, sectionY, force)
	local section = chunk.sections[sectionY]
	if not section then
		return
	end
	if force then
		section.queuedForce = true
	end
	if section.queued then
		return
	end
	section.queued = true
	table.insert(renderQueue, { chunk = chunk, sy = sectionY })
	queueSorted = false
end

-- Lowest top of the ground in a chunk (world block y): per column the highest full cube, the lowest of those
local function surfaceOf(chunk)
	local ys = {}
	for sectionY in pairs(chunk.sections) do
		table.insert(ys, sectionY)
	end
	table.sort(ys, function(a, b)
		return a > b
	end)
	local found = table.create(256, false)
	local left = 256
	local lowest = math.huge
	for _, sectionY in ipairs(ys) do
		local section = chunk.sections[sectionY]
		local occ = classify(section)
		local cells = section.cells
		for ly = 15, 0, -1 do
			local base = ly * 256
			for column = 1, 256 do
				if not found[column] and occ[cellAt(cells, base + column) + 1] then
					found[column] = true
					left -= 1
					local y = sectionY * 16 + ly
					if y < lowest then
						lowest = y
					end
				end
			end
			if left == 0 then
				return lowest
			end
		end
	end
	return dimInfo(chunk.dim).minY -- a column without ground (void, a hole to the bottom): everything from the bottom
end

-- A chunk arrived: the faces of its neighbours toward it may be seen now (air there) - only those sections again
local NEIGHBOURS = {
	-- dx, dz, the neighbour's side that faces the new chunk, the new chunk's border cells (x or z = fixed)
	{ 1, 0, "west", "x", 15 },
	{ -1, 0, "east", "x", 0 },
	{ 0, 1, "north", "z", 15 },
	{ 0, -1, "south", "z", 0 },
}
local function recheckNeighbours(chunk)
	for _, side in ipairs(NEIGHBOURS) do
		local other = world.chunks[chunkKey(chunk.x + side[1], chunk.z + side[2], chunk.dim)]
		if not other then
			continue
		end
		for sectionY, section in pairs(other.sections) do
			if not (section.waits and section.waits[side[3]]) or not section.built then
				continue
			end
			local mine = chunk.sections[sectionY]
			local open = mine == nil
			if mine then
				local occ = classify(mine)
				local cells = mine.cells
				for a = 0, 15 do
					for b = 0, 15 do
						local i = if side[4] == "x" then cellIndex(side[5], a, b) else cellIndex(b, a, side[5])
						if not occ[cellAt(cells, i) + 1] then
							open = true
							break
						end
					end
					if open then
						break
					end
				end
			end
			if open then
				queueSection(other, sectionY, false)
			else
				section.waits[side[3]] = nil -- solid wall there: those faces stay hidden
			end
		end
	end
end

-- Builds queued sections, nearest first, for at most BUDGET seconds per frame
RunService.Heartbeat:Connect(function()
	if #renderQueue == 0 or not world.info then
		return
	end
	local now = os.clock()
	if not queueSorted and now - queueSortedAt > 0.25 then
		queueSorted = true
		queueSortedAt = now
		local points = loader.points or {}
		for _, entry in ipairs(renderQueue) do
			local best = math.huge
			for _, point in ipairs(points) do
				local dx, dz, dy = entry.chunk.x - point.cx, entry.chunk.z - point.cz, entry.sy - point.sy
				local d = dx * dx + dz * dz + dy * dy * 0.25
				if d < best then
					best = d
				end
			end
			entry.d = best
		end
		table.sort(renderQueue, function(a, b)
			return a.d > b.d -- far first: the nearest is taken from the end
		end)
	end
	while #renderQueue > 0 and os.clock() - now < BUDGET do
		local entry = table.remove(renderQueue)
		local chunk = entry.chunk
		local section = chunk.sections[entry.sy]
		if section and section.queued and world.chunks[chunkKey(chunk.x, chunk.z, chunk.dim)] == chunk then
			section.queued = false
			local force = section.queuedForce == true
			section.queuedForce = nil
			local t0 = os.clock()
			local ok, err = pcall(buildSection, chunk, entry.sy, section, force)
			local spent = os.clock() - t0
			buildStats.count += 1
			buildStats.total += spent
			buildStats.longest = math.max(buildStats.longest, spent)
			if not ok then
				warn("[MinecraftWorld] section " .. chunkKey(chunk.x, chunk.z, chunk.dim) .. " y " .. entry.sy .. ": " .. tostring(err))
			end
		end
	end
end)

local function renderAll(force)
	for _, chunk in pairs(world.chunks) do
		for sectionY, section in pairs(chunk.sections) do
			if section.built or section.queued then
				queueSection(chunk, sectionY, force)
			end
		end
	end
end

-- Blocks (states) Minecraft has not sent the look of yet (they appear in the world) and items it has not described yet
-- (they come into an inventory): ask for them in one call, then build again
local askQueue = { blocks = {}, items = {} }
local newLooks = {} -- block name -> true: its look came / changed since the last afterNewPictures
local askScheduled = false
local mergeBlocks -- below (adds an assets answer)
local afterNewPictures -- below (re-render + tell the clients)
local loadItemIcons -- below
local loadSkyPictures -- below
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
		local ok, result = pcall(client.Call, client, ASSETS, { blocks = blocks, items = items }, { Timeout = 30 })
		if world.assets ~= assets then
			return -- everything was loaded again meanwhile
		end
		if ok and type(result) == "table" then
			mergeBlocks(assets, result)
			-- what did not fit into this answer (about 40 KiB): asked for in the next call
			local later = type(result.later) == "table" and result.later or {}
			local laterBlocks, laterItems = {}, {}
			for _, name in ipairs(if type(later.blocks) == "table" then later.blocks else {}) do
				laterBlocks[name] = true
			end
			for _, id in ipairs(if type(later.items) == "table" then later.items else {}) do
				laterItems[id] = true
			end
			for index = #blocks, 1, -1 do
				if laterBlocks[blocks[index]] then
					table.insert(askQueue.blocks, 1, blocks[index])
				end
			end
			for index = #items, 1, -1 do
				if laterItems[items[index]] then
					table.insert(askQueue.items, 1, items[index])
				end
			end
			for _, name in ipairs(blocks) do
				if not assets.blocks[name] and not laterBlocks[name] then
					assets.other[name] = true
				end
			end
			afterNewPictures()
		else
			log(string.format("pictures: Minecraft did not answer (%s) - asked again later", tostring(result)))
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
	local dim = tonumber(data.d) or 0
	local key = chunkKey(data.x, data.z, dim)
	local old = world.chunks[key]
	-- a chunk loaded again (after /fill, ...): its parts that are still right stay, only the changes are rebuilt
	local folder = if old then old.folder else Instance.new("Folder")
	folder.Name = "Chunk " .. key
	local chunk = { x = data.x, z = data.z, dim = dim, sections = {}, folder = folder }
	if type(data.signs) == "table" then
		chunk.signs = {}
		for _, sign in ipairs(data.signs) do
			if type(sign) == "table" and type(sign[1]) == "number" then
				chunk.signs[sign[1] .. "," .. sign[2] .. "," .. sign[3]] = sign
			end
		end
	end
	if data.v == 2 then
		chunk.sections = decodePacked(data)
		noticeBlocks(data.palette or {})
	else
		for _, sectionData in ipairs(data.sections or {}) do
			chunk.sections[sectionData.y] = decodeSection(sectionData)
			noticeBlocks(sectionData.palette or {})
		end
	end
	for sectionY, section in pairs(chunk.sections) do
		local before = old and old.sections[sectionY]
		if before then
			section.parts = before.parts
			section.built = before.built
			old.sections[sectionY] = nil
		end
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
	chunk.surface = surfaceOf(chunk)
	chunk.renderFrom = renderFromOf(chunk)
	for sectionY, section in pairs(chunk.sections) do
		if sectionY >= chunk.renderFrom or section.built then
			queueSection(chunk, sectionY, false) -- (a built section below the window: buildSection takes it away)
		end
	end
	recheckNeighbours(chunk)
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
		dims = info.dims, -- (every dimension at its own height: the clients check blocks against their own one)
		textures = assets.textures,
		blocks = assets.blocks,
		items = assets.items,
		tabs = assets.tabs,
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
	-- animated (water, lava): h = one frame, the pixels hold all frames one below the other
	local frames = if type(texture.frames) == "number" and texture.frames > 1 then math.floor(texture.frames) else 1
	if not ok or #raw ~= texture.w * texture.h * 4 * frames then
		return nil
	end
	local decoded = { w = texture.w, h = texture.h, pixels = buffer.fromstring(raw) }
	if frames > 1 then
		decoded.frames = frames
		decoded.frametime = if type(texture.frametime) == "number" then math.max(1, texture.frametime) else 1
		decoded.order = if type(texture.order) == "table" then texture.order else nil
	end
	if type(texture.span) == "number" and texture.span > 0 then
		decoded.span = texture.span -- (one picture covers this many blocks: water / lava flowing)
	end
	return decoded
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

-- itemPictures false: the item list of the first call has no pictures yet - those items are NOT known (else
-- their icons would never be asked for: everything stayed a plain square until the block was placed once)
function mergeBlocks(assets, result, itemPictures: boolean?)
	for key, texture in pairs(result.textures or {}) do
		assets.textures[key] = decodeTexture(texture)
	end
	for name, look in pairs(result.blocks or {}) do
		if lookComplete(assets, look) then
			assets.blocks[name] = look
			assets.other[name] = nil
			newLooks[name] = true -- (afterNewPictures: only sections with these blocks are built again)
		else
			assets.other[name] = true
		end
	end
	for _, item in ipairs(if itemPictures ~= false and type(result.items) == "table" then result.items else {}) do
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
		mergeBlocks(assets, result, false)
		for name, key in pairs(result.gui or {}) do
			if assets.textures[key] then
				assets.gui[name] = key
			end
		end
		if type(result.items) == "table" and #result.items > 0 then
			assets.items = result.items -- the creative inventory (in this order)
		end
		if type(result.tabs) == "table" then
			assets.tabs = result.tabs -- Minecraft's creative tabs: [{id, name, icon, items = [ids]}]
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
	-- Minecraft's creative tabs (all its items, in its order) - on their own (~35 KB)
	local tabsOk, tabsResult = pcall(client.Call, client, ASSETS, { tabs = true }, { Timeout = 30 })
	if generation ~= world.generation or world.assets ~= assets then
		return
	end
	if tabsOk and type(tabsResult) == "table" and type(tabsResult.tabs) == "table" and #tabsResult.tabs > 0 then
		assets.tabs = tabsResult.tabs
		assetsChanged:FireAllClients(clientAssets())
	end
	local ids = {}
	local seen = {}
	local function want(id)
		if type(id) == "string" and not seen[id] and not assets.itemsById[id] then
			seen[id] = true
			assets.asked["item " .. id] = true
			table.insert(ids, id)
		end
	end
	for _, item in ipairs(assets.items) do
		want(item.id)
	end
	for _, tab in ipairs(assets.tabs or {}) do
		for _, id in ipairs(type(tab.items) == "table" and tab.items or {}) do
			want(id)
		end
	end
	-- Minecraft answers about 40 KiB at a time (one piece over Bridge - bigger answers came in 4 KiB chunks, one HTTP
	-- request each, and took longer than the time limit), the rest it lists in "later": asked for right away
	local failures, shownAt = 0, os.clock()
	while #ids > 0 do
		local batch = table.move(ids, 1, math.min(MAX_ASK, #ids), 1, {})
		local ok, result = pcall(client.Call, client, ASSETS, { items = batch }, { Timeout = 45 })
		if generation ~= world.generation or world.assets ~= assets then
			return
		end
		if not ok or type(result) ~= "table" then
			failures += 1
			if failures >= 3 then
				log(string.format("item icons: Minecraft did not answer (%s) - %d items without an icon for now",
					tostring(result), #ids))
				for _, id in ipairs(ids) do
					assets.asked["item " .. id] = nil -- (asked again when it shows up in an inventory)
				end
				break
			end
			task.wait(2)
			continue
		end
		mergeBlocks(assets, result)
		local later = {}
		local laterItems = type(result.later) == "table" and result.later.items
		for _, id in ipairs(if type(laterItems) == "table" then laterItems else {}) do
			later[id] = true
		end
		local rest = {}
		for index, id in ipairs(ids) do
			if index > #batch or later[id] then
				table.insert(rest, id)
			end
		end
		if #rest >= #ids then
			break -- (nothing came: do not ask forever)
		end
		ids = rest
		if os.clock() - shownAt > 3 then
			shownAt = os.clock()
			afterNewPictures() -- (the first ones are there already)
		end
	end
	log(string.format("item icons from Minecraft: %d", count(assets.itemsById)))
	afterNewPictures()
end

-- The pictures of the sky (sun, the 8 moon phases, rain, snow, clouds) - also after the world, like the item icons
-- More pictures from Minecraft in one call: {hud = true} (particles, attack indicator, effect boxes, hunger),
-- {effects = true} (the icons of all status effects)
local function loadPictureSet(generation, request, label)
	local assets = world.assets
	if not assets or not assets.available then
		return
	end
	for _ = 1, 3 do
		local ok, result = pcall(client.Call, client, ASSETS, request, { Timeout = 45 })
		if generation ~= world.generation or world.assets ~= assets then
			return
		end
		if ok and type(result) == "table" then
			local added = 0
			for key, texture in pairs(type(result.textures) == "table" and result.textures or {}) do
				assets.textures[key] = decodeTexture(texture)
				added += 1
			end
			for name, key in pairs(type(result.gui) == "table" and result.gui or {}) do
				if assets.textures[key] then
					assets.gui[name] = key
				end
			end
			log(string.format("%s pictures from Minecraft: %d", label, added))
			assetsChanged:FireAllClients(clientAssets())
			return
		end
		task.wait(2)
	end
end

function loadSkyPictures(generation)
	local assets = world.assets
	if not assets or not assets.available then
		return
	end
	for _ = 1, 3 do
		local ok, result = pcall(client.Call, client, ASSETS, { sky = true }, { Timeout = 45 })
		if generation ~= world.generation or world.assets ~= assets then
			return
		end
		if ok and type(result) == "table" then
			local added = 0
			for key, texture in pairs(type(result.textures) == "table" and result.textures or {}) do
				assets.textures[key] = decodeTexture(texture)
				added += 1
			end
			for name, key in pairs(type(result.gui) == "table" and result.gui or {}) do
				if assets.textures[key] then
					assets.gui[name] = key
				end
			end
			log(string.format("sky pictures from Minecraft: %d", added))
			afterNewPictures()
			return
		end
		task.wait(2)
	end
	log("sky pictures: Minecraft did not answer - the sky without its pictures")
end

function afterNewPictures()
	-- only the sections that have one of the blocks with a new look are built again (a real world has thousands of
	-- sections: building all of them every few seconds while the item icons come would never stop)
	if next(newLooks) ~= nil then
		local names = newLooks
		newLooks = {}
		local function again(chunk, sectionY)
			local section = chunk and chunk.sections[sectionY]
			if section and (section.built or section.queued) then
				queueSection(chunk, sectionY, false)
			end
		end
		for _, chunk in pairs(world.chunks) do
			for sectionY, section in pairs(chunk.sections) do
				if section.built or section.queued then
					for _, name in ipairs(section.palette) do
						if names[name] then
							-- this section, and its neighbours (a grey placeholder hid their faces toward it)
							again(chunk, sectionY)
							again(chunk, sectionY + 1)
							again(chunk, sectionY - 1)
							again(world.chunks[chunkKey(chunk.x + 1, chunk.z, chunk.dim)], sectionY)
							again(world.chunks[chunkKey(chunk.x - 1, chunk.z, chunk.dim)], sectionY)
							again(world.chunks[chunkKey(chunk.x, chunk.z + 1, chunk.dim)], sectionY)
							again(world.chunks[chunkKey(chunk.x, chunk.z - 1, chunk.dim)], sectionY)
							break
						end
					end
				end
			end
		end
	end
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

-- region loading: the chunks around the players (like Minecraft's render distance)
local LOADERS = 2 -- chunk calls at the same time (one waits for Minecraft, the other one already asks)

-- Where the players are (chunk, section) - the spawn while nobody is there
local function playerPoints()
	local info = world.info
	local scale = info.studsPerBlock
	local points = {}
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if root and root:IsA("BasePart") then
			local p = root.Position
			local bx = math.floor(p.X / scale)
			local by = math.floor(p.Y / scale) + info.minY
			local bz = math.floor(p.Z / scale)
			if not (waitingPlatform and p.Y > 1000 and p.Y < 2000) then -- (not on the waiting platform)
				table.insert(points, { cx = bx // 16, cz = bz // 16, sy = by // 16, root = root, dim = dimAt(by) })
			end
		end
	end
	local has = #points > 0
	if not has then
		local spawn = info.spawn
		table.insert(points, { cx = spawn[1] // 16, cz = spawn[3] // 16, sy = spawn[2] // 16, dim = 0 })
	end
	return points, has
end

-- The chunks that should be there, nearest first: {key, cx, cz, d2}
local function wantedChunks(points)
	local info = world.info
	local list = {}
	if not info.follow then
		-- an older mod: only its area around the spawn
		for dx = -info.radius, info.radius do
			for dz = -info.radius, info.radius do
				local cx, cz = info.center[1] + dx, info.center[2] + dz
				table.insert(list, { chunkKey(cx, cz), cx, cz, dx * dx + dz * dz, 0 })
			end
		end
	else
		local seen = {}
		local limit = (VIEW + 0.5) * (VIEW + 0.5)
		for _, point in ipairs(points) do
			for dx = -VIEW, VIEW do
				for dz = -VIEW, VIEW do
					local d2 = dx * dx + dz * dz
					if d2 <= limit then
						local cx, cz = point.cx + dx, point.cz + dz
						local key = chunkKey(cx, cz, point.dim)
						local known = seen[key]
						if not known then
							known = { key, cx, cz, d2, point.dim or 0 }
							seen[key] = known
							table.insert(list, known)
						elseif d2 < known[4] then
							known[4] = d2
						end
					end
				end
			end
		end
	end
	table.sort(list, function(a, b)
		return a[4] < b[4]
	end)
	return list
end

local function pickBatch()
	local now = os.clock()
	local batch = {}
	local points = loader.points or playerPoints()
	for _, item in ipairs(wantedChunks(points)) do
		local key = item[1]
		if (not world.chunks[key] or loader.reload[key]) and not loader.inFlight[key] and (loader.retryAt[key] or 0) <= now then
			table.insert(batch, item)
			if #batch >= CHUNKS_PER_CALL then
				break
			end
		end
	end
	return batch
end

local function loaderWorker(generation)
	while generation == world.generation do
		local batch = pickBatch()
		if #batch == 0 then
			task.wait(0.2)
			continue
		end
		local coords = {}
		for _, item in ipairs(batch) do
			loader.inFlight[item[1]] = true
			-- ([cx, cz] in the overworld, [cx, cz, dimension] elsewhere)
			table.insert(coords, if (item[5] or 0) ~= 0 then { item[2], item[3], item[5] } else { item[2], item[3] })
		end
		local ok, result = pcall(client.Call, client, CHUNKS, { chunks = coords, v = 2 }, { Timeout = 30 })
		for _, item in ipairs(batch) do
			loader.inFlight[item[1]] = nil
		end
		if generation ~= world.generation then
			return
		end
		local now = os.clock()
		if not ok or type(result) ~= "table" then
			warn("[MinecraftWorld] loading chunks failed: " .. tostring(result))
			for _, item in ipairs(batch) do
				loader.retryAt[item[1]] = now + 3
			end
			task.wait(1)
			continue
		end
		local answered = {}
		for _, data in ipairs(result.chunks or {}) do
			if type(data) == "table" and type(data.x) == "number" and type(data.z) == "number" then
				local key = chunkKey(data.x, data.z, tonumber(data.d) or 0)
				answered[key] = true
				if data.later then
					loader.retryAt[key] = now + 0.3 -- Minecraft loads / generates it meanwhile
				elseif data.outside then
					loader.retryAt[key] = now + 10
				else
					loader.reload[key] = nil
					loader.retryAt[key] = nil
					local applied, err = pcall(applyChunk, data)
					if not applied then
						warn("[MinecraftWorld] chunk " .. key .. ": " .. tostring(err))
						loader.retryAt[key] = now + 5
					end
					task.wait() -- (unpacking a chunk takes ~10-20 ms: one per frame, the server never stands still)
					if generation ~= world.generation then
						return
					end
				end
			end
		end
		for _, item in ipairs(batch) do
			if not answered[item[1]] then
				loader.retryAt[item[1]] = now + 1
			end
		end
	end
end

local function unloadChunk(key, chunk)
	world.chunks[key] = nil
	loader.reload[key] = nil
	chunk.folder:Destroy()
end

-- Is the ground around this place built (the section there, the one below and above)?
local function placeReady(cx, cz, sy, dim)
	local chunk = world.chunks[chunkKey(cx, cz, dim)]
	if not chunk then
		return false
	end
	for y = sy - 1, sy + 1 do
		local section = chunk.sections[y]
		-- (a built section that only waits to be built again - a new look came - is ground enough)
		if section and not section.built and (section.queued or y >= chunk.renderFrom) then
			return false
		end
	end
	return true
end

_G.MinecraftWorldBuildStats = buildStats -- (tests read it)
local function worldStats()
	local chunks, sections, parts = 0, 0, 0
	for _, chunk in pairs(world.chunks) do
		chunks += 1
		for _, section in pairs(chunk.sections) do
			if section.built then
				sections += 1
				for _ in pairs(section.parts) do
					parts += 1
				end
			end
		end
	end
	return chunks, sections, parts
end

local function manage()
	local info = world.info
	local points, has = playerPoints()
	loader.points = points
	loader.hasPlayers = has
	local floors = {} -- dimension -> lowest section of its players - BELOW
	for _, point in ipairs(points) do
		local d = point.dim or 0
		floors[d] = math.min(floors[d] or math.huge, point.sy - BELOW)
	end
	loader.playerFloor = floors
	-- the vertical window of every chunk follows the players
	for _, chunk in pairs(world.chunks) do
		local from = renderFromOf(chunk)
		local current = chunk.renderFrom
		if from < current then
			chunk.renderFrom = from
			for sectionY in pairs(chunk.sections) do
				if sectionY >= from and sectionY < current then
					queueSection(chunk, sectionY, false)
				end
			end
		elseif from > current + 1 then -- (one section of slack: going up and down a bit builds nothing new)
			chunk.renderFrom = from
			for sectionY, section in pairs(chunk.sections) do
				if sectionY < from and section.built then
					queueSection(chunk, sectionY, false) -- buildSection takes it away
				end
			end
		end
	end
	-- far chunks go (only while somebody is there - nobody there: keep what is built)
	if has and info.follow then
		local limit = (VIEW + 2) * (VIEW + 2)
		for key, chunk in pairs(world.chunks) do
			local near = false
			for _, point in ipairs(points) do
				local dx, dz = chunk.x - point.cx, chunk.z - point.cz
				if dx * dx + dz * dz <= limit and (point.dim or 0) == (chunk.dim or 0) then
					near = true
					break
				end
			end
			if not near then
				unloadChunk(key, chunk)
			end
		end
		for key, at in pairs(loader.retryAt) do
			if at < os.clock() - 30 then
				loader.retryAt[key] = nil
			end
		end
	end
	-- the first time the ground at the spawn is there: the characters come
	if not world.loaded then
		local spawn = info.spawn
		local cx, cz, sy = spawn[1] // 16, spawn[3] // 16, spawn[2] // 16
		local ready = true
		for dx = -1, 1 do
			for dz = -1, 1 do
				if not placeReady(cx + dx, cz + dz, sy) then
					ready = false
				end
			end
		end
		if ready then
			world.loaded = true
			local chunks, sections, parts = worldStats()
			log(string.format("Minecraft world there: %d chunks, %d sections, %d parts, %.1f s (more loads around the players)",
				chunks, sections, parts, os.clock() - world.loadStarted))
			onWorldReady()
		end
		return
	end
	-- a character where the ground is not built yet (teleported, walked fast): it waits there instead of falling
	for _, point in ipairs(points) do
		local root = point.root
		if root then
			if not placeReady(point.cx, point.cz, point.sy, point.dim) then
				if not root.Anchored then
					root.Anchored = true
					root:SetAttribute("McWaitWorld", true)
				end
			elseif root:GetAttribute("McWaitWorld") then
				root:SetAttribute("McWaitWorld", nil)
				root.Anchored = false
			end
		end
	end
end

task.spawn(function()
	while true do
		task.wait(0.25)
		if world.info then
			local ok, err = pcall(manage)
			if not ok then
				warn("[MinecraftWorld] world manager: " .. tostring(err))
			end
		end
	end
end)

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
	table.clear(renderQueue)
	table.clear(loader.retryAt)
	table.clear(loader.inFlight)
	table.clear(loader.reload)
	world.loadStarted = os.clock()
	-- The pictures first (small): the chunks are then built with textures right away
	loadAssets(generation)
	task.spawn(loadItemIcons, generation) -- all item icons at the same time as the world (the clients get them at once)
	task.spawn(loadSkyPictures, generation)
	task.spawn(loadPictureSet, generation, { hud = true }, "HUD")
	task.spawn(loadPictureSet, generation, { effects = true }, "effect")
	task.spawn(loadPictureSet, generation, { containers = true }, "container")
	if generation ~= world.generation then
		return
	end
	log(if info.follow then string.format("loading the world around the players (%d chunks around everybody)", VIEW)
		else "loading the area around the spawn (older mod)")
	for _ = 1, LOADERS do
		task.spawn(loaderWorker, generation)
	end
end
-- endregion

-- region changes
local function sectionAt(blockX, blockY, blockZ, create)
	local chunkX, chunkZ = math.floor(blockX / 16), math.floor(blockZ / 16)
	local chunk = world.chunks[chunkKey(chunkX, chunkZ, dimAt(blockY))]
	if not chunk then
		return nil
	end
	local sectionY = math.floor(blockY / 16)
	local section = chunk.sections[sectionY]
	if not section and create then
		section = { palette = { "minecraft:air" }, cells = newCells(), parts = {} }
		chunk.sections[sectionY] = section
	end
	return chunk, sectionY, section
end

local breakParticles -- below (a block breaks: Minecraft's crumbs of its picture)
local function applyBlocks(blocks)
	local dirty = {}
	local names = {}
	local crumbs = 0
	for _, block in ipairs(blocks) do
		local x, y, z, name = block[1], block[2], block[3], block[4]
		table.insert(names, name)
		if type(x) == "number" and type(y) == "number" and type(z) == "number" and type(name) == "string" then
			local chunk, sectionY, section = sectionAt(x, y, z, true)
			if chunk and section and crumbs < 8 and AIR[baseName(name)] then
				local before = section.palette[cellAt(section.cells, cellIndex(x - chunk.x * 16, y - sectionY * 16, z - chunk.z * 16)) + 1]
				if before and not AIR[baseName(before)] then
					crumbs += 1
					breakParticles(x, y, z, before)
				end
			end
			if chunk and section then
				local paletteIndex = table.find(section.palette, name)
				if not paletteIndex then
					table.insert(section.palette, name)
					paletteIndex = #section.palette
				end
				local lx, ly, lz = x - chunk.x * 16, y - sectionY * 16, z - chunk.z * 16
				setCell(section.cells, cellIndex(lx, ly, lz), paletteIndex - 1)
				dirty[section] = { chunk, sectionY }
				-- the neighbours on a border: their faces toward this block may be seen now - or not any more
				-- (and water below may now have water above it)
				local function mark(other, otherY)
					local otherSection = other and other.sections[otherY]
					if otherSection then
						dirty[otherSection] = { other, otherY }
					end
				end
				if ly == 0 then mark(chunk, sectionY - 1) end
				if ly == 15 then mark(chunk, sectionY + 1) end
				if lx == 0 then mark(world.chunks[chunkKey(chunk.x - 1, chunk.z, chunk.dim)], sectionY) end
				if lx == 15 then mark(world.chunks[chunkKey(chunk.x + 1, chunk.z, chunk.dim)], sectionY) end
				if lz == 0 then mark(world.chunks[chunkKey(chunk.x, chunk.z - 1, chunk.dim)], sectionY) end
				if lz == 15 then mark(world.chunks[chunkKey(chunk.x, chunk.z + 1, chunk.dim)], sectionY) end
			end
		end
	end
	for section, place in pairs(dirty) do
		if place[2] >= (place[1].renderFrom or -math.huge) then
			section.queued = false -- (at once, not in the queue)
			buildSection(place[1], place[2], section, false)
		end
	end
	noticeBlocks(names)
end

breakParticles = function(x, y, z, name)
	local info = world.info
	local look = world.assets and world.assets.blocks[name]
	if not info or not look then
		return
	end
	local key = look.particle or (look.faces and (look.faces.north or look.faces.up))
	if not key and type(look.parts) == "table" and look.parts[1] and type(look.parts[1].f) == "table" then
		for _, picture in pairs(look.parts[1].f) do
			key = picture
			break
		end
	end
	if type(key) ~= "string" then
		return
	end
	local scale = info.studsPerBlock
	particlesRemote:FireAllClients("break", Vector3.new((x + 0.5) * scale, (y - info.minY + 0.5) * scale, (z + 0.5) * scale), key)
end

local function blockAt(x, y, z)
	local chunk, sectionY, section = sectionAt(x, y, z, false)
	if not chunk or not section then
		return "minecraft:air"
	end
	local index = cellAt(section.cells, cellIndex(x - chunk.x * 16, y - sectionY * 16, z - chunk.z * 16))
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
	-- armor (the bar above his hearts, Minecraft's damage reduction) + experience (the green bar, his level)
	player:SetAttribute("McArmor", tonumber(state.armor) or 0)
	player:SetAttribute("McToughness", tonumber(state.tough) or 0)
	if type(state.xp) == "table" then
		player:SetAttribute("McXpLevel", tonumber(state.xp[1]) or 0)
		player:SetAttribute("McXpProgress", tonumber(state.xp[2]) or 0)
	end
	-- the item in his hand (every client shows it at his right arm)
	local held = state.slots[37 + (tonumber(state.sel) or 0)]
	local character = player.Character
	if character then
		character:SetAttribute("McHeld", if type(held) == "table" and type(held.id) == "string" then held.id else nil)
	end
end

--[[
	Where his character is (studs). The client says where it was when he clicked: the server's copy is a moment behind
	(while jumping up a pillar it is still in the block he builds below him - Minecraft would refuse the block, or it
	came too late and pushed him off). Believed when it is close to the server's copy (CLIENT_SLACK blocks).
]]
local CLIENT_SLACK = 3
local function rootOf(player, claimed)
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	if not root then
		return nil
	end
	local scale = world.info and world.info.studsPerBlock or 3
	if typeof(claimed) == "Vector3" and claimed.X == claimed.X and claimed.Y == claimed.Y and claimed.Z == claimed.Z
		and (claimed - root.Position).Magnitude <= CLIENT_SLACK * scale then
		return claimed
	end
	return root.Position
end

-- where his feet are, in Minecraft blocks (at = his root where the client had it, see rootOf)
local function feetOf(player, at)
	local position = at or rootOf(player)
	local info = world.info
	if not position or not info then
		return nil
	end
	local scale = info.studsPerBlock
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

-- Somebody's character stands in the block (Minecraft's hitbox: 0.6 x 1.8 blocks from the feet up; touching is not
-- standing in it, like Minecraft). The one who builds: where his client had him (placerRoot, see rootOf)
local TOUCH = 0.01 -- studs
local function characterInBlock(center, scale, placer, placerRoot)
	for _, other in ipairs(Players:GetPlayers()) do
		local character = other.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if root and character:GetAttribute("McGameMode") ~= "spectator" then
			local p = if other == placer and placerRoot then placerRoot else root.Position
			local half = scale / 2
			local feet = p.Y - Character.ROOT_HEIGHT
			local width = Character.HITBOX.X / 2
			if math.abs(p.X - center.X) < half + width - TOUCH and math.abs(p.Z - center.Z) < half + width - TOUCH
				and feet < center.Y + half - TOUCH and feet + Character.HITBOX.Y > center.Y - half + TOUCH then
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
	Clicked: a cube Minecraft says a click does nothing on (look.use false: dirt, grass, logs, planks - not a crafting
	table, a pumpkin); sneaking with something in the hand never uses the block (Minecraft). Looks from before "use"
	existed: no state, not *_table / jukebox (the old guess).
	Returns the cell it showed the block in.
]]
local function clickBuilds(clicked, look, sneaking)
	if not look or look.cube ~= true or look.single or look.fluid then
		return false
	end
	if look.use ~= nil then
		return look.use ~= true or sneaking
	end
	return not string.find(clicked, "[", 1, true) and (sneaking or not string.find(baseName(clicked), "_table$"))
		and baseName(clicked) ~= "minecraft:jukebox"
end

local function guessPlacement(player, x, y, z, face, slot, sneaking, root)
	local mode = gameModeOf(player)
	local state = states[player]
	local normal = FACE_NAMES[face]
	if (mode ~= "creative" and mode ~= "survival") or not state or not normal or not slot then
		return nil
	end
	local stack = state.slots[37 + slot] -- hotbar slot 0-8 = menu slots 36-44
	local item = type(stack) == "table" and itemInfo(stack.id)
	local block = item and item.block
	if type(block) ~= "string" or string.find(block, "[", 1, true) then
		return nil
	end
	local blockLook = world.assets and world.assets.blocks[block]
	if blockLook and (blockLook.cube ~= true or blockLook.single or blockLook.fluid) then
		return nil -- (a flower, a torch: where they may stand, Minecraft decides)
	end
	local clicked = blockAt(x, y, z)
	if not clickBuilds(clicked, world.assets and world.assets.blocks[clicked], sneaking) then
		return nil
	end
	local px, py, pz = x + normal.X, y + normal.Y, z + normal.Z
	local info = world.info
	if not AIR[baseName(blockAt(px, py, pz))] or not insideWorld(py) then
		return nil
	end
	local scale = info.studsPerBlock
	local center = Vector3.new((px + 0.5) * scale, (py - info.minY + 0.5) * scale, (pz + 0.5) * scale)
	if characterInBlock(center, scale, player, root) then
		return nil
	end
	applyBlocks({ { px, py, pz, block } })
	return px .. "," .. py .. "," .. pz
end

--[[
	Clicks come quickly (jumping up a pillar: a click every 4 ticks), Minecraft answers each one a moment later. The
	answer of an earlier click must not undo what a later click already showed (it was refused - the block below is
	still air in its answer - while the next one is already standing): shownBy remembers which click showed what
	where; answers of older clicks leave those blocks alone.
]]
local editCount = 0
local shownBy = {} -- "x,y,z" -> number of the click that showed a block there before Minecraft answered

local function answerBlocks(number, blocks)
	local keep = {}
	for _, entry in ipairs(blocks) do
		if type(entry) == "table" and type(entry[1]) == "number" and type(entry[2]) == "number"
			and type(entry[3]) == "number" then
			local key = entry[1] .. "," .. entry[2] .. "," .. entry[3]
			local by = shownBy[key]
			if by and by > number then
				continue -- (a later click showed something here: its answer says what Minecraft made of it)
			end
			if by then
				shownBy[key] = nil
			end
			table.insert(keep, entry)
		end
	end
	return keep
end

-- info = {face = "up" | ..., hit = Vector3 (studs), slot = 0..8, look = Vector3, ground = boolean, root = Vector3
-- (where his client had him), id = number (the client's click: "answer" goes back to him when Minecraft answered)}
local function onEdit(player, action, x, y, z, info)
	if (action ~= "use" and action ~= "break") or not isWhole(x) or not isWhole(y) or not isWhole(z) then
		return
	end
	info = if type(info) == "table" then info else {}
	local worldInfo = world.info
	if not world.loaded or not worldInfo or not insideWorld(y) or not allowEdit(player) then
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
	editCount += 1
	local number = editCount
	local clickId = if isWhole(info.id) then info.id else nil
	local at = rootOf(player, info.root)
	if action == "break" then
		if AIR[baseName(blockAt(x, y, z))] then
			return
		end
		applyBlocks({ { x, y, z, "minecraft:air" } }) -- shown at once; Minecraft confirms (or puts it back)
		shownBy[x .. "," .. y .. "," .. z] = number
	end
	swingArm(player)
	local hit = typeof(info.hit) == "Vector3" and info.hit or center
	local slot = if isWhole(info.slot) and info.slot >= 0 and info.slot <= 8 then info.slot else nil
	-- right click into the air (no block in reach): only the item is used - a bucket, a snowball (x, y, z = his eyes)
	local air = action == "use" and info.air == true
	if action == "use" and not air then
		local shown = guessPlacement(player, x, y, z, info.face, slot,
			character ~= nil and character:GetAttribute("McSneak") == true, at)
		if shown then
			shownBy[shown] = number
		end
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
			feet = feetOf(player, at),
			slot = slot,
			sneak = character ~= nil and character:GetAttribute("McSneak") == true,
			ground = info.ground ~= false,
			air = if air then true else nil,
		}, { Timeout = 10 })
		if ok and type(result) == "table" then
			if type(result.blocks) == "table" then
				applyBlocks(answerBlocks(number, result.blocks)) -- what Minecraft made of it (not broken = back again)
			end
			if result.state then
				setState(player, result.state)
			end
			if result.ok ~= true and Config.Debug then
				log(string.format("%s: %s at %d %d %d - %s", player.Name, action, x, y, z, tostring(result.reason)))
			end
		else
			log(string.format("%s: %s at %d %d %d not possible (%s)", player.Name, action, x, y, z, tostring(result)))
			for key, by in pairs(shownBy) do
				if by == number then
					shownBy[key] = nil
				end
			end
			-- (load that chunk again: the loaders take it first)
			local key = chunkKey(chunk.x, chunk.z, chunk.dim)
			loader.reload[key] = true
			loader.retryAt[key] = nil
		end
		if clickId and player.Parent then
			editRemote:FireClient(player, "answer", clickId) -- (his client's own block: Minecraft has spoken)
		end
	end)
end

editRemote.OnServerEvent:Connect(onEdit)

-- The inventory (E): Minecraft's own clicks, creative items, middle click, Q
inventoryRemote.OnServerEvent:Connect(function(player, op, a, b, c, d)
	if type(op) ~= "string" or not allowEdit(player) then
		return
	end
	if op == "click" and isWhole(a) and (a == -999 or (a >= 0 and a <= (if d == true then 90 else 45))) then
		inOrder(player, function()
			-- d = true: a slot of the open chest / furnace window (its own numbers, up to 90)
			callPlayer(player, "click", { slot = a, button = if b == 1 then 1 else 0, shift = c == true, feet = feetOf(player),
				container = d == true })
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
	elseif op == "trade" and isWhole(a) and a >= 0 and a < 64 then
		-- a trade chosen in the villager's list
		inOrder(player, function()
			callPlayer(player, "trade", { index = a })
		end)
	elseif op == "button" and isWhole(a) and a >= 0 and a <= 64 then
		-- a button of the open window (enchanting table offer ...): Minecraft's clickMenuButton
		inOrder(player, function()
			callPlayer(player, "button", { id = a })
		end)
	elseif op == "release" and isWhole(a) and a >= 0 and a <= 8 and type(b) == "number" and b == b then
		-- a bow / crossbow / trident let go after b seconds (looking c): Minecraft shoots / throws it
		local look = if typeof(c) == "Vector3" and c.Magnitude > 0.01 then c.Unit else nil
		inOrder(player, function()
			callPlayer(player, "release", { slot = a, ticks = math.floor(math.clamp(b, 0, 3600) * 20),
				feet = feetOf(player), look = if look then { look.X, look.Y, look.Z } else nil })
		end)
	elseif op == "eat" and isWhole(a) and a >= 0 and a <= 8 then
		-- eaten / drunk (his client counted Minecraft's time): Minecraft does the item (effects, bowl ...), the food
		-- goes into his hunger here (FoodData.eat: food + nutrition, saturation + its saturation, at most the food)
		inOrder(player, function()
			local result = callPlayer(player, "eat", { slot = a, feet = feetOf(player) })
			if result and result.ok and type(result.food) == "number" then
				local state = hungerOf(player)
				state.food = math.clamp(state.food + result.food, 0, 20)
				state.sat = math.clamp(state.sat + (tonumber(result.sat) or 0), 0, state.food)
				showHunger(player, state)
			end
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
	lastSwing[player] = now
	if now - (swingTokens[player] or 0) >= 0.1 then
		swingTokens[player] = now
		swingArm(player)
	end
end)
Players.PlayerRemoving:Connect(function(player)
	swingTokens[player] = nil
	lastSwing[player] = nil
end)

-- region health + damage
local function onDied(player)
	hunger[player] = nil -- (Minecraft: after dying the food is full again)
	if killedByCommand[player] then
		killedByCommand[player] = nil -- Minecraft did it already
		return
	end
	local hurtBy = lastHurt[player]
	local cause = if hurtBy and os.clock() - hurtBy.at < 10 then hurtBy.cause else "other"
	-- Minecraft's death: the message for everybody, the inventory falls out where he died (unless keepInventory)
	local result = callPlayer(player, "died", { feet = feetOf(player), cause = cause })
	-- he comes back where Minecraft says: his bed / respawn anchor (another dimension too) - or the world spawn
	if result and type(result.respawn) == "table" then
		player:SetAttribute("McRespawn", Vector3.new(tonumber(result.respawn[1]) or 0, tonumber(result.respawn[2]) or 0,
			tonumber(result.respawn[3]) or 0))
	end
	if result and result.noBed == true then
		chatRemote:FireClient(player, "reply", { "You have no home bed or charged respawn anchor, or it was obstructed" })
	end
end

local function setupHealth(character)
	do
		local owner = Players:GetPlayerFromCharacter(character)
		local spot = owner and owner:GetAttribute("McRespawn")
		if owner and typeof(spot) == "Vector3" then
			owner:SetAttribute("McRespawn", nil)
			task.defer(function()
				local root = character:WaitForChild("HumanoidRootPart", 5)
				if root and root:IsA("BasePart") then
					root.CFrame = CFrame.new(spot)
					root.Anchored = true -- (manage() lets go when the ground there is built)
					root:SetAttribute("McWaitWorld", true)
				end
			end)
		end
	end
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
local exhaustNext = {} -- player -> exhaustion to add (hurt() comes before the hunger region)
-- Minecraft's armor for the damage Roblox counts itself (lava, fire, a hot floor, cactus): CombatRules.getDamageAfterAbsorb
-- (hits from Minecraft - mobs, players - come already reduced)
local afterArmor
do
	local ARMORED = { lava = true, fire = true, cactus = true }
	function afterArmor(player, amount, cause)
		if not ARMORED[cause] then
			return amount
		end
		local armor = tonumber(player:GetAttribute("McArmor")) or 0
		local toughness = tonumber(player:GetAttribute("McToughness")) or 0
		if armor <= 0 then
			return amount
		end
		local f = 2 + toughness / 4
		local g = math.clamp(armor - amount / f, armor * 0.2, 20)
		return amount * (1 - g / 25)
	end
end

local function hurt(player, amount, from, cause)
	amount = afterArmor(player, amount, cause)
	local character = player.Character
	local humanoid = character and character:FindFirstChildOfClass("Humanoid")
	local mode = gameModeOf(player)
	if not humanoid or humanoid.Health <= 0 or amount <= 0 or mode == "creative" or mode == "spectator" then
		return
	end
	lastHurt[player] = { cause = cause, at = os.clock() }
	if cause == "attack" then
		exhaustNext[player] = (exhaustNext[player] or 0) + 0.1 -- (Minecraft: being hit makes hungry)
	end
	humanoid:TakeDamage(amount)
	Character.flashRed(character)
	hurtRemote:FireClient(player, amount, from)
end

-- region hunger: Minecraft's FoodData counted here (food 20, saturation, exhaustion), the food comes from Minecraft's items
--[[
	Exhaustion like Minecraft: sprinting 0.1 per block, swimming 0.01 per block, a jump 0.05 (sprinting 0.2), a hit 0.1,
	a broken block 0.005, being hurt 0.1. Every 4 exhaustion: 1 saturation, without saturation 1 food. Healing: full food
	+ saturation = fast (every 10 ticks), 18+ food = every 80 ticks (costs 6 exhaustion), 0 food = starving (every
	80 ticks 1 damage: easy down to 10, normal down to 1, hard to death). Peaceful: food and health come back.
	Shown with the player attributes McFood / McSaturation (the client draws the drumsticks).
]]
function hungerOf(player)
	local state = hunger[player]
	if not state then
		state = { food = 20, sat = 5, exhaustion = 0, timer = 0, peaceful = 0, last = nil, rising = false }
		hunger[player] = state
	end
	return state
end
local function exhaust(player, amount)
	local state = hungerOf(player)
	state.exhaustion = math.min(40, state.exhaustion + amount)
end
function showHunger(player, state)
	if player:GetAttribute("McFood") ~= state.food then
		player:SetAttribute("McFood", state.food)
	end
	local saturation = math.floor(state.sat * 10 + 0.5) / 10
	if player:GetAttribute("McSaturation") ~= saturation then
		player:SetAttribute("McSaturation", saturation)
	end
end
local function heal(humanoid, amount)
	humanoid.Health = math.min(humanoid.MaxHealth, humanoid.Health + amount)
end

local function hungerTick(player, state, humanoid, root, difficulty)
	-- what he did this tick
	local position = root.Position
	local scale = world.info and world.info.studsPerBlock or 3
	if state.last then
		local moved = Vector3.new(position.X - state.last.X, 0, position.Z - state.last.Z).Magnitude / scale
		if moved < 2 then -- (a teleport is no walk)
			local character = player.Character
			if character and character:GetAttribute("McSwimming") == true or player:GetAttribute("McFluid") ~= nil then
				exhaust(player, 0.01 * moved)
			elseif character and character:GetAttribute("McSprint") == true then
				exhaust(player, 0.1 * moved)
			end
		end
	end
	state.last = position
	local rising = root.AssemblyLinearVelocity.Y > Character.JUMP_VELOCITY * 0.7
	if rising and not state.rising and player:GetAttribute("McFluid") == nil
		and not (player.Character and player.Character:GetAttribute("McFlying") == true) then
		exhaust(player, if player.Character and player.Character:GetAttribute("McSprint") == true then 0.2 else 0.05)
	end
	state.rising = rising
	-- Minecraft's FoodData.tick
	if state.exhaustion > 4 then
		state.exhaustion -= 4
		if state.sat > 0 then
			state.sat = math.max(state.sat - 1, 0)
		elseif difficulty ~= "peaceful" then
			state.food = math.max(state.food - 1, 0)
		end
	end
	local hurtable = humanoid.Health < humanoid.MaxHealth
	if difficulty == "peaceful" then
		-- Player.aiStep: peaceful gives health every 20 ticks and food every 10 ticks back
		state.peaceful += 1
		if state.peaceful % 20 == 0 and hurtable then
			heal(humanoid, 1)
		end
		if state.peaceful % 10 == 0 and state.food < 20 then
			state.food += 1
		end
	end
	if state.sat > 0 and hurtable and state.food >= 20 then
		state.timer += 1
		if state.timer >= 10 then
			local amount = math.min(state.sat, 6)
			heal(humanoid, amount / 6)
			exhaust(player, amount)
			state.timer = 0
		end
	elseif state.food >= 18 and hurtable then
		state.timer += 1
		if state.timer >= 80 then
			heal(humanoid, 1)
			exhaust(player, 6)
			state.timer = 0
		end
	elseif state.food <= 0 then
		state.timer += 1
		if state.timer >= 80 then
			if humanoid.Health > 10 or difficulty == "hard" or (humanoid.Health > 1 and difficulty == "normal") then
				hurt(player, 1, nil, "starve")
			end
			state.timer = 0
		end
	else
		state.timer = 0
	end
end

-- region dangers like Minecraft: below the world (the void), lava, fire, magma, cactus, burning afterwards
local dangers
do
	local burning = {} -- player -> os.clock() until he burns (Minecraft: 15 s after lava, 8 s after fire)
	local dangerAt = {} -- player -> os.clock() of the last damage (Minecraft's 10 ticks without new damage)
	local burnAt = {} -- player -> os.clock() of the last burn damage (1 per second)
	local function effectOn(player, id)
		return string.find(tostring(player:GetAttribute("McEffects") or ""), '"' .. id .. '"', 1, true) ~= nil
	end
	function dangers(player, mode, humanoid, root)
		local info = world.info
		local scale = info.studsPerBlock
		local p = root.Position
		local feetY = (p.Y - Character.ROOT_HEIGHT) / scale + info.minY
		local dim = dimInfo(dimAt(feetY))
		local now = os.clock()
		local character = player.Character
		local protected = mode == "creative" or mode == "spectator"
		if feetY < dim.minY - 64 and mode ~= "spectator" then
			-- below the world: Minecraft's "fell out of the world" (4 every tick, in creative too)
			lastHurt[player] = { cause = "void", at = now }
			humanoid:TakeDamage(4)
			return
		end
		if protected then
			burning[player] = nil
			if character then
				character:SetAttribute("McBurning", nil)
			end
			return
		end
		local x, z = math.floor(p.X / scale), math.floor(p.Z / scale)
		local fy = math.floor(feetY + 0.01)
		local feetBlock = baseName(blockAt(x, fy, z))
		local bodyBlock = baseName(blockAt(x, fy + 1, z))
		local fireProof = effectOn(player, "fire_resistance")
		local amount, cause = 0, nil
		if feetBlock == "minecraft:water" or bodyBlock == "minecraft:water" then
			burning[player] = nil -- (water puts it out)
		end
		if feetBlock == "minecraft:lava" or bodyBlock == "minecraft:lava" then
			amount, cause = 4, "lava"
			burning[player] = now + 15
		elseif feetBlock == "minecraft:fire" or feetBlock == "minecraft:soul_fire" or bodyBlock == "minecraft:fire" then
			amount, cause = if feetBlock == "minecraft:soul_fire" then 2 else 1, "fire"
			burning[player] = math.max(burning[player] or 0, now + 8)
		elseif feetBlock == "minecraft:campfire" or feetBlock == "minecraft:soul_campfire" then
			local lit = string.find(blockAt(x, fy, z) or "", "lit=true", 1, true) ~= nil
			if lit and not (character and character:GetAttribute("McSneak") == true) then
				amount, cause = 1, "fire"
			end
		elseif baseName(blockAt(x, math.floor(feetY - 0.05), z)) == "minecraft:magma_block"
			and not (character and character:GetAttribute("McSneak") == true) then
			amount, cause = 1, "fire" -- (Minecraft: a hot floor, not while sneaking)
		else
			-- a cactus next to him (Minecraft: touching it hurts 1)
			local fx, fz = p.X / scale - x, p.Z / scale - z
			local sides = {}
			if fx < 0.32 then table.insert(sides, { -1, 0 }) end
			if fx > 0.68 then table.insert(sides, { 1, 0 }) end
			if fz < 0.32 then table.insert(sides, { 0, -1 }) end
			if fz > 0.68 then table.insert(sides, { 0, 1 }) end
			for _, side in ipairs(sides) do
				for dy = 0, 1 do
					if baseName(blockAt(x + side[1], fy + dy, z + side[2])) == "minecraft:cactus" then
						amount, cause = 1, "cactus"
					end
				end
			end
			if baseName(blockAt(x, fy, z)) == "minecraft:sweet_berry_bush" and (root.AssemblyLinearVelocity.Magnitude > 0.5) then
				amount, cause = 1, "cactus"
			end
		end
		if fireProof and cause ~= "cactus" then
			amount, cause = 0, nil
			burning[player] = nil
		end
		local onFire = burning[player] ~= nil and now < burning[player]
		if not onFire then
			burning[player] = nil
		end
		if character and (character:GetAttribute("McBurning") == true) ~= onFire then
			character:SetAttribute("McBurning", if onFire then true else nil) -- (the clients show the flames)
		end
		if amount > 0 and now - (dangerAt[player] or 0) >= 0.5 then
			dangerAt[player] = now
			hurt(player, amount, nil, cause)
		elseif amount == 0 and onFire and now - (burnAt[player] or 0) >= 1 then
			burnAt[player] = now
			hurt(player, 1, nil, "burn")
		end
	end
	Players.PlayerRemoving:Connect(function(player)
		burning[player] = nil
		dangerAt[player] = nil
		burnAt[player] = nil
	end)
end

local hungerClock = 0
RunService.Heartbeat:Connect(function(dt)
	hungerClock += dt
	if hungerClock < 0.05 then
		return
	end
	local ticks = math.min(10, math.floor(hungerClock / 0.05))
	hungerClock -= ticks * 0.05
	local difficulty = world.info and world.info.difficulty or "normal"
	for _, player in ipairs(Players:GetPlayers()) do
		local mode = gameModeOf(player)
		local character = player.Character
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if humanoid and humanoid.Health > 0 and root and world.loaded and not root.Anchored then
			local ok, err = pcall(dangers, player, mode, humanoid, root)
			if not ok then
				warn("[MinecraftWorld] dangers: " .. tostring(err))
			end
		end
		if (mode == "survival" or mode == "adventure") and humanoid and humanoid.Health > 0 and root then
			local state = hungerOf(player)
			if exhaustNext[player] then
				exhaust(player, exhaustNext[player])
				exhaustNext[player] = nil
			end
			for _ = 1, ticks do
				hungerTick(player, state, humanoid, root, difficulty)
			end
			showHunger(player, state)
		end
	end
end)
Players.PlayerRemoving:Connect(function(player)
	hunger[player] = nil
end)
-- endregion

-- Minecraft: falling more than 3 blocks hurts 1 per block more (not while flying)
fallRemote.OnServerEvent:Connect(function(player, blocks)
	local character = player.Character
	if type(blocks) == "number" and blocks == blocks and blocks > 3
		and not (character and character:GetAttribute("McFlying") == true) then
		hurt(player, math.ceil(math.min(blocks, 400) - 3), nil, "fall")
	end
end)

-- Minecraft: the air under water is out -> 2 damage (every second, the client counts the air like Minecraft). Only
-- when his head (or, swimming, his body) really is in water here.
local drownedAt = {}
drownRemote.OnServerEvent:Connect(function(player)
	local now = os.clock()
	local info = world.info
	local character = player.Character
	local root = character and character:FindFirstChild("HumanoidRootPart")
	if now - (drownedAt[player] or 0) < 0.9 or not info or not root then
		return
	end
	local scale = info.studsPerBlock
	local feetY = (root.Position.Y - Character.ROOT_HEIGHT) / scale + info.minY
	local x, z = math.floor(root.Position.X / scale), math.floor(root.Position.Z / scale)
	for _, eye in ipairs({ 1.62, 0.4 }) do -- (standing / swimming: Minecraft's eye heights)
		if baseName(blockAt(x, math.floor(feetY + eye), z)) == "minecraft:water" then
			drownedAt[player] = now
			hurt(player, 2, nil, "drown")
			return
		end
	end
end)

-- A Roblox player hits a Minecraft player's NPC: Minecraft does the damage (with knockback from our mannequin)
local attackedAt = {}
local interactAt = {}
attackRemote.OnServerEvent:Connect(function(player, model, how, mobId)
	if model == nil and type(mobId) == "number" and type(how) == "table" and how.use == true then
		-- a right click on a mob (trading, milking, shearing, feeding ...): Minecraft's interactOn
		local now = os.clock()
		if now - (interactAt[player] or 0) < 0.2 then
			return
		end
		interactAt[player] = now
		swingArm(player)
		inOrder(player, function()
			callPlayer(player, "interact", { mob = mobId, feet = feetOf(player) })
		end)
		return
	end
	if model == nil and type(mobId) == "number" then
		-- a mob: Minecraft's attack by his stand-in (the item in his hand, crit, sweep, knockback - Minecraft checks reach)
		local now = os.clock()
		if gameModeOf(player) == "spectator" or now - (attackedAt[player] or 0) < 1 / ATTACKS_PER_SECOND then
			return
		end
		attackedAt[player] = now
		local since = now - (lastSwing[player] or 0)
		lastSwing[player] = now
		local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
		local falling = type(how) == "table" and how.falling == true and root ~= nil and root.AssemblyLinearVelocity.Y < 2
		local sprint = type(how) == "table" and how.sprint == true
		exhaustNext[player] = (exhaustNext[player] or 0) + 0.1
		swingArm(player)
		task.spawn(function()
			local ok, result = pcall(client.Call, client, HURT, { mob = mobId, attacker = player.UserId, since = since,
				falling = falling, sprint = sprint, feet = feetOf(player) }, { Timeout = 10 })
			if ok and type(result) == "table" and type(result.at) == "table" then
				local info = world.info
				if info then
					local scale = info.studsPerBlock
					local at = Vector3.new((tonumber(result.at[1]) or 0) * scale, ((tonumber(result.at[2]) or 0) - info.minY + 1) * scale,
						(tonumber(result.at[3]) or 0) * scale)
					if result.crit then
						particlesRemote:FireAllClients("crit", at)
					end
					if result.magic then
						particlesRemote:FireAllClients("magic", at)
					end
				end
			end
			if type(result) == "table" and result.state then
				setState(player, result.state) -- (the sword wears)
			end
		end)
		return
	end
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
	-- Minecraft decides the damage with his item (charge since the last swing, critical hit when falling)
	local since = now - (lastSwing[player] or 0)
	lastSwing[player] = now
	local falling = type(how) == "table" and how.falling == true and root.AssemblyLinearVelocity.Y < 2
	local sprint = type(how) == "table" and how.sprint == true
	exhaustNext[player] = (exhaustNext[player] or 0) + 0.1 -- (Minecraft: a hit makes hungry)
	swingArm(player)
	task.spawn(function()
		local ok, result = pcall(client.Call, client, HURT, { target = target, amount = 1, attacker = player.UserId,
			since = since, falling = falling, sprint = sprint }, { Timeout = 10 })
		if not ok then
			if Config.Debug then
				warn("[MinecraftWorld] hit not sent: " .. tostring(result))
			end
			return
		end
		if type(result) == "table" and npcRoot.Parent then
			local at = npcRoot.Position + Vector3.new(0, 1, 0)
			if result.crit then
				particlesRemote:FireAllClients("crit", at)
			end
			if result.magic then
				particlesRemote:FireAllClients("magic", at)
			end
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
				-- (cause: "attack" | "explosion" | "other" - a zombie, an arrow, a creeper, /kill ...)
				local cause = if type(content.cause) == "string" then content.cause else "attack"
				hurt(player, math.clamp(tonumber(content.amount) or 0, 0, 1000), from, cause)
				local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
				if root then
					if content.crit then
						particlesRemote:FireAllClients("crit", root.Position + Vector3.new(0, 1, 0))
					end
					if content.magic then
						particlesRemote:FireAllClients("magic", root.Position + Vector3.new(0, 1, 0))
					end
				end
			end
		end
	elseif content.type == "mc.effects" then
		-- his status effects from Minecraft: the client shows the icons + moves like Minecraft (speed, jump boost ...)
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				local ok, text = pcall(HttpService.JSONEncode, HttpService, if type(content.list) == "table" then content.list else {})
				if ok then
					player:SetAttribute("McEffects", text)
				end
				local character = player.Character
				if character then
					local invisible = false
					for _, effect in ipairs(if type(content.list) == "table" then content.list else {}) do
						if type(effect) == "table" and effect.id == "invisibility" then
							invisible = true
						end
					end
					character:SetAttribute("McInvisible", invisible) -- (the other clients hide him)
				end
			end
		end
	elseif content.type == "mc.effect" then
		-- Minecraft's effect ticks: regeneration heals 1, poison hurts 1 (never below 1), wither hurts 1
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				local humanoid = player.Character and player.Character:FindFirstChildOfClass("Humanoid")
				if humanoid and humanoid.Health > 0 then
					if content.kind == "regen" then
						humanoid.Health = math.min(humanoid.MaxHealth, humanoid.Health + 1)
					elseif content.kind == "poison" and humanoid.Health > 1 then
						hurt(player, 1, nil, "poison")
					elseif content.kind == "wither" then
						hurt(player, 1, nil, "wither")
					end
				end
			end
		end
	elseif content.type == "mc.player" then
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				setState(player, content.state)
			end
		end
	elseif content.type == "mc.title" then
		-- what Minecraft shows only to him (/title @s, /tellraw @s ...): chat lines into his chat, the rest on screen
		for _, player in ipairs(Players:GetPlayers()) do
			if player.UserId == content.u then
				if content.kind == "chat" and type(content.text) == "string" then
					chatRemote:FireClient(player, "reply", { content.text })
				else
					titleRemote:FireClient(player, {
						kind = tostring(content.kind), text = if type(content.text) == "string" then content.text else "",
						color = tonumber(content.color), fadeIn = tonumber(content.fadeIn), stay = tonumber(content.stay),
						fadeOut = tonumber(content.fadeOut), reset = content.reset == true,
					})
				end
			end
		end
	elseif content.type == "mc.teleport" and type(content.p) == "table" then
		-- a portal took him (Minecraft's own portal code found the exit): his character goes there - another
		-- dimension is another height in this world; it waits there until the ground is built
		for _, player in ipairs(Players:GetPlayers()) do
			local character = player.Character
			local root = character and character:FindFirstChild("HumanoidRootPart")
			if player.UserId == content.u and root then
				local at = Vector3.new(tonumber(content.p[1]) or 0, tonumber(content.p[2]) or 0, tonumber(content.p[3]) or 0)
				local yaw = tonumber(content.yaw)
				local turn = if yaw then CFrame.Angles(0, yaw, 0) else (root.CFrame - root.Position)
				root.AssemblyLinearVelocity = Vector3.zero
				root.CFrame = CFrame.new(at) * turn -- (the whole character: its joints hang on the root)
				root.Anchored = true -- (manage() lets go when the ground there is built)
				root:SetAttribute("McWaitWorld", true)
				log(player.Name .. " went through a portal (dimension " .. tostring(content.dim) .. ")")
			end
		end
	end
end)
-- endregion

-- Sneaking / sprinting / flying: attributes on the character - the client scripts show the pose, PlayerSync sends it
moveRemote.OnServerEvent:Connect(function(player, sneak, sprint, pitch, flying, swimming)
	local character = player.Character
	if character then
		local mode = gameModeOf(player)
		character:SetAttribute("McSwimming", swimming == true and mode ~= "spectator") -- (PlayerSync: "sm")
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

local turnFaces -- below (/drehen)
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

--[[
	Top / Bottom pictures: Roblox does not document which way a Texture lies on the Top / Bottom face of a part. Minecraft's
	up face has north at the top of the picture. If the tops look turned in Roblox (an observer's arrow, planks), turn
	them for everybody: "/drehen oben 90" (0, 90, 180, 270; "unten" for the bottom faces) - try until it looks like in
	Minecraft, then put the number into MinecraftWorldConfig (TopTurn / BottomTurn) so it stays.
]]
ReplicatedStorage:SetAttribute("McTopTurn", tonumber(Config.TopTurn) or 0)
ReplicatedStorage:SetAttribute("McBottomTurn", tonumber(Config.BottomTurn) or 0)

turnFaces = function(player, rest)
	local which, amount = string.match(string.lower(rest), "^(%S+)%s+(%-?%d+)$")
	amount = tonumber(amount)
	local attribute = if which == "oben" or which == "top" then "McTopTurn"
		elseif which == "unten" or which == "bottom" then "McBottomTurn" else nil
	if not attribute or not amount or amount % 90 ~= 0 then
		reply(player, { "/drehen oben <0|90|180|270>  oder  /drehen unten <0|90|180|270>",
			string.format("jetzt: oben %d, unten %d", ReplicatedStorage:GetAttribute("McTopTurn") or 0,
				ReplicatedStorage:GetAttribute("McBottomTurn") or 0) })
		return
	end
	ReplicatedStorage:SetAttribute(attribute, amount % 360)
	reply(player, { string.format("Bilder %s um %d Grad gedreht (für alle). Passt es? Dann in MinecraftWorldConfig %s = %d eintragen.",
		if attribute == "McTopTurn" then "oben" else "unten", amount % 360,
		if attribute == "McTopTurn" then "TopTurn" else "BottomTurn", amount % 360) })
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
		elseif word and string.lower(word) == "drehen" then
			turnFaces(player, rest or "")
		elseif word and string.lower(word) == "welt" then
			local chunks, sections, parts = worldStats()
			reply(player, { string.format("Welt: %d Chunks, %d Abschnitte gebaut, %d Parts, %d warten noch, Sichtweite %d Chunks",
				chunks, sections, parts, #renderQueue, VIEW), string.format("Bauen: %d Abschnitte, im Schnitt %.1f ms, längster %.1f ms",
				buildStats.count, buildStats.total / math.max(1, buildStats.count) * 1000, buildStats.longest * 1000) })
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

-- region mobs (topic mcworld.mobs -> every client; their looks once per kind from Minecraft: mcworld.mob {id})
do -- (a block: its locals do not count towards the script's 200)
	local mobsRemote = remote("RemoteEvent", "Mobs") -- server -> clients: (list) like the topic
	local mobModel = remote("RemoteFunction", "MobModel") -- client asks: (id, type) -> {parts, textures} or nil
	local mobLooks = {} -- type -> look | false (Minecraft has none) | "waiting"
	if Config.Mobs ~= false then
		client:Subscribe(nil, MOBS, function(data)
			if type(data) == "table" and type(data.mobs) == "table" then
				mobsRemote:FireAllClients(data.mobs)
			end
		end, { Latest = true })
	end
	mobModel.OnServerInvoke = function(_player, id, kind)
		if type(id) ~= "number" or type(kind) ~= "string" or #kind > 100 then
			return nil
		end
		local started = os.clock()
		while mobLooks[kind] == "waiting" and os.clock() - started < 10 do
			task.wait(0.1)
		end
		local known = mobLooks[kind]
		if known ~= nil and known ~= "waiting" then
			return known or nil
		end
		mobLooks[kind] = "waiting"
		local ok, result = pcall(client.Call, client, MOB, { id = id }, { Timeout = 15 })
		if not ok or type(result) ~= "table" or result.ok ~= true then
			-- a dedicated server has no models: never again; anything else (mob gone, no answer): ask again later
			local reason = if ok and type(result) == "table" then tostring(result.reason or "") else ""
			mobLooks[kind] = if string.find(reason, "dedicated", 1, true) then false else nil
			if Config.Debug then
				warn("[MinecraftWorld] mob " .. kind .. ": " .. tostring(if ok and type(result) == "table" then result.reason else result))
			end
			return nil
		end
		local textures = {}
		for key, texture in pairs(type(result.textures) == "table" and result.textures or {}) do
			textures[key] = decodeTexture(texture)
		end
		-- (a painting: no parts, its picture + size in blocks)
		local look = { parts = if type(result.parts) == "table" then result.parts else {}, textures = textures,
			picture = result.picture, w = result.w, h = result.h }
		mobLooks[kind] = look
		return look
	end
end
-- endregion

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

-- region day, night, weather (Minecraft's own sky values -> attributes of Lighting; the clients draw it: MinecraftSky)
do
	local Lighting = game:GetService("Lighting")
	local function color3(value, fallback)
		if type(value) == "table" and type(value[1]) == "number" and type(value[2]) == "number" and type(value[3]) == "number" then
			return Color3.fromRGB(math.clamp(value[1], 0, 255), math.clamp(value[2], 0, 255), math.clamp(value[3], 0, 255))
		end
		return fallback
	end
	local function alpha(value)
		return if type(value) == "table" and type(value[4]) == "number" then math.clamp(value[4] / 255, 0, 1) else 0
	end
	client:Subscribe(nil, SKY, function(data)
		if type(data) ~= "table" or type(data.t) ~= "number" then
			return
		end
		local scale = world.info and world.info.studsPerBlock or 3
		local minY = world.info and world.info.minY or -64
		local values = {
			McTime = data.t, McTimeRate = tonumber(data.rate) or 20,
			McSkyColor = color3(data.sky, Color3.fromRGB(120, 167, 255)),
			McFogColor = color3(data.fog, Color3.fromRGB(192, 216, 255)),
			McWaterFogColor = color3(data.waterFog, Color3.fromRGB(5, 5, 51)),
			McSkyLightColor = color3(data.skyLightColor, Color3.new(1, 1, 1)),
			McBlockLightColor = color3(data.blockLight, Color3.fromRGB(255, 216, 140)),
			McAmbientColor = color3(data.ambient, Color3.fromRGB(10, 10, 10)),
			McSunriseColor = color3(data.sunrise, Color3.new(1, 0.8, 0.2)), McSunriseAlpha = alpha(data.sunrise),
			McCloudColor = color3(data.cloud, Color3.new(1, 1, 1)), McCloudAlpha = alpha(data.cloud),
			McSunAngle = tonumber(data.sun) or 0, McMoonAngle = tonumber(data.moon) or 180,
			McStarAngle = tonumber(data.star) or 0, McStarBrightness = tonumber(data.stars) or 0,
			McMoonPhase = if type(data.phase) == "string" then data.phase else "full_moon",
			McSkyLight = tonumber(data.skyLight) or 1,
			McFogEnd = (tonumber(data.fogEnd) or 1024) * scale, McWaterFogEnd = (tonumber(data.waterFogEnd) or 96) * scale,
			McCloudHeight = ((tonumber(data.cloudHeight) or 192.33) - minY) * scale,
			McRain = tonumber(data.rain) or 0, McThunder = tonumber(data.thunder) or 0,
			McPrecipitation = if type(data.precipitation) == "string" then data.precipitation else "none",
			McWaterColor = color3(data.waterColor, Color3.fromRGB(63, 118, 228)),
		}
		-- the sky of the other dimensions (Nether, End) - JSON, the clients there use it instead
		local dimsText = ""
		if type(data.dims) == "table" then
			local ok, text = pcall(HttpService.JSONEncode, HttpService, data.dims)
			dimsText = if ok then text else ""
		end
		values.McDimSky = dimsText
		for name, value in pairs(values) do
			if Lighting:GetAttribute(name) ~= value then
				Lighting:SetAttribute(name, value)
			end
		end
	end, { Latest = true })
end
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
	if type(data.signs) == "table" then
		-- a sign's new text: on its board at once (its model stays)
		for _, sign in ipairs(data.signs) do
			if type(sign) == "table" and type(sign[1]) == "number" and type(sign[2]) == "number" and type(sign[3]) == "number" then
				local chunk = sectionAt(sign[1], sign[2], sign[3], false)
				if chunk then
					chunk.signs = chunk.signs or {}
					chunk.signs[sign[1] .. "," .. sign[2] .. "," .. sign[3]] = sign
					local at = Vector3.new(sign[1], sign[2], sign[3])
					for _, model in ipairs(chunk.folder:GetChildren()) do
						if model:IsA("Model") and model:GetAttribute("McBlock") == at then
							setSignText(model, sign)
						end
					end
				end
			end
		end
	end
	if type(data.chunks) == "table" then
		-- very many changes there (explosion, /fill): those chunks are loaded again (the loaders take them first)
		for _, pair in ipairs(data.chunks) do
			local key = type(pair) == "table" and chunkKey(pair[1], pair[2], tonumber(pair[3]) or 0)
			if key and world.chunks[key] then
				loader.reload[key] = true
				loader.retryAt[key] = nil
			end
		end
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
