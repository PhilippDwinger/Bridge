--[[
	MinecraftClient - the Minecraft side of the player (LocalScript in StarterPlayerScripts)

	- Textures: the server got the pictures from Minecraft (RemoteFunction GetAssets). EditableImages only exist on
	  the client, so they are made here and put on every Texture with the attribute "McTexture" in the world - and the
	  skins (RemoteFunction GetSkin) on every body part with "McSkinFace". Every picture is made once and kept; one
	  that fails is tried again (no grey blocks any more). Studio / game: Game Settings > Security > "Allow Mesh /
	  Image APIs" must be on.
	- The player is a Minecraft player in Minecraft: his game mode and inventory live there (the server sends them:
	  RemoteEvent Inventory "state"). Hotbar (keys 1-9, mouse wheel) with the item counts, inventory (E): survival /
	  adventure = Minecraft's inventory with its own clicks (left / right / shift, the 2x2 crafting grid), creative =
	  the creative inventory (all items, scroll with the wheel, a tab for the normal inventory). Q throws the item
	  away (Ctrl + Q the whole stack), the middle mouse button picks the block you look at.
	- Health like Minecraft: 10 hearts over the hotbar (not in creative / spectator), fall damage (more than 3
	  blocks), left click on a Minecraft player hits him, hits from Minecraft players come with a red flash, a tilted
	  camera and knockback.
	- Building: aimed from the eyes like in Minecraft (MinecraftPlayer says where they are and where they look).
	  Right click = use (Minecraft decides: a door, a lever, a button - or it places the item in the hand), left click
	  = break: creative at once, survival after Minecraft's breaking time with the cracks, adventure not at all,
	  spectator nothing. The server sends it to Minecraft over Bridge; Minecraft's own code does it.
	Camera, walking, flying, sneaking / sprinting, the animations and the chat: MinecraftPlayer.
]]
local AssetService = game:GetService("AssetService")
local ContextActionService = game:GetService("ContextActionService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local StarterGui = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")

local Images = require(ReplicatedStorage:WaitForChild("MinecraftImages"))
local remotes = ReplicatedStorage:WaitForChild("MinecraftWorld")
local getAssets = remotes:WaitForChild("GetAssets") :: RemoteFunction
local assetsChanged = remotes:WaitForChild("AssetsChanged") :: RemoteEvent
local editRemote = remotes:WaitForChild("Edit") :: RemoteEvent
local attackRemote = remotes:WaitForChild("Attack") :: RemoteEvent
local fallRemote = remotes:WaitForChild("Fall") :: RemoteEvent
local hurtRemote = remotes:WaitForChild("Hurt") :: RemoteEvent
local swingRemote = remotes:WaitForChild("Swing") :: RemoteEvent
local getSkin = remotes:WaitForChild("GetSkin") :: RemoteFunction
local inventoryRemote = remotes:WaitForChild("Inventory") :: RemoteEvent
local miningSpeed = remotes:WaitForChild("MiningSpeed") :: RemoteFunction
local drownRemote = remotes:WaitForChild("Drown") :: RemoteEvent

local player = Players.LocalPlayer
local REPEAT_BREAK = 0.25 -- creative: 5 ticks between two blocks while the button is held (also after a block broke)
local REPEAT_USE = 0.2 -- 4 ticks between two right clicks while the button is held
local eating: any -- {id, use, started, duration, crumbsAt} while eating / drinking (region eating, below)
local startEating: () -> boolean
local stopEating: () -> ()
local spawnParticle: any -- region particles (below)
local TEXTURE_SCALE = 8 -- world textures: every Minecraft pixel becomes 8x8 (sharp also where Roblox smooths)
local ANIMATED_SCALE = 4 -- moving pictures (water, lava: up to 32 frames each) a bit smaller
local ICON_SIZE = 64 -- (a slot is 16 Minecraft pixels, 48 screen pixels at the biggest GUI scale)
local HOTBAR_KEYS = {
	[Enum.KeyCode.One] = 1, [Enum.KeyCode.Two] = 2, [Enum.KeyCode.Three] = 3, [Enum.KeyCode.Four] = 4,
	[Enum.KeyCode.Five] = 5, [Enum.KeyCode.Six] = 6, [Enum.KeyCode.Seven] = 7, [Enum.KeyCode.Eight] = 8,
	[Enum.KeyCode.Nine] = 9,
}
-- Top / Bottom faces of Roblox parts: how much their pictures have to be turned (clockwise) to look like Minecraft's
-- (Minecraft's up face: north at the top of the picture). 0 = Roblox lays them the same way.
local TOP_TURN = 0
local BOTTOM_TURN = 0

local assets = nil -- what the server sent (see MinecraftWorld: clientAssets)
local imagesFailed = false -- the very first picture failed: "Allow Mesh / Image APIs" is off

-- region inventory state (from Minecraft)
--[[
	state = {gm, sel, slots, carried} - slots[i] = Minecraft's menu slot i - 1: 1 crafting result, 2-5 crafting
	grid, 6-9 armour, 10-36 inventory, 37-45 hotbar, 46 offhand; each false or {id, n, name, max, bar?}
]]
local state: any = { gm = "survival", sel = 0, slots = table.create(46, false), carried = false }
local stateArrived = false
local selected = 1 -- hotbar slot 1-9 (chosen here, Minecraft gets it with every click)
local inventoryOpen = false
local inventoryView = "survival" -- "survival" | "creative" (the window that is open)
local creativeCursor = nil -- creative inventory: the item on the mouse {id, n} (only here until it is put down)

local function gameMode(): string
	if stateArrived and type(state.gm) == "string" then
		return state.gm
	end
	local mode = player:GetAttribute("McGameMode")
	return if type(mode) == "string" then mode else "survival"
end

local function stackAt(menuSlot: number): any
	local stack = state.slots[menuSlot + 1]
	return if type(stack) == "table" then stack else nil
end

local function hotbarStack(slot: number): any
	return stackAt(35 + slot) -- hotbar 1-9 = menu slots 36-44
end

local function itemInfo(id: string?): any
	if type(id) ~= "string" or not assets then
		return nil
	end
	if assets.itemsById and assets.itemsById[id] then
		return assets.itemsById[id]
	end
	for _, item in ipairs(assets.items or {}) do
		if item.id == id then
			return item
		end
	end
	return nil
end

-- Minecraft: reach 4.5 blocks in survival / adventure, 5 in creative; Minecraft players: 3 / 5
local function reach(): number
	return if gameMode() == "creative" then 5 else 4.5
end

local function attackReach(): number
	return if gameMode() == "creative" then 5 else 3
end
-- endregion

-- region pictures
--[[
	Every picture is made once and kept (key -> EditableImage): new pictures from Minecraft only add the missing ones,
	nothing that is shown gets destroyed. A picture that could not be made (memory, too many at once) is tried again
	a moment later - and every Texture that has no picture yet waits in "waiting" until it gets one. (Before, all
	pictures were made again after every change and one failure stopped all the rest: whole block kinds went grey.)
]]
local cache = {} -- cache key -> {image = EditableImage, content = Content, source = (what it was made from)}
local failedAt = {} -- cache key -> os.clock() of the last failure
local waiting = setmetatable({}, { __mode = "k" }) -- Texture -> true: still without its picture
local RETRY = 2 -- seconds

-- source: what the picture is made from - a string, or the texture table itself (compared by identity: a new
-- answer from Minecraft brings new tables; comparing the pixels as a string cost a 1-32 KB string per call)
local function makeImage(cacheKey: string, source: any, build: () -> any): Content?
	local cached = cache[cacheKey]
	if cached and cached.source == source then
		return cached.content
	end
	if imagesFailed or (failedAt[cacheKey] and os.clock() - failedAt[cacheKey] < RETRY) then
		return nil
	end
	local picture = build()
	local ok, image = pcall(function()
		return AssetService:CreateEditableImage({ Size = Vector2.new(picture.w, picture.h) })
	end)
	if not ok or not image then
		failedAt[cacheKey] = os.clock()
		if next(cache) == nil then
			imagesFailed = true
			warn("[MinecraftWorld] no textures: turn on 'Allow Mesh / Image APIs' (Game Settings > Security) - " .. tostring(image))
		else
			warn("[MinecraftWorld] picture " .. cacheKey .. " not made (" .. tostring(image) .. ") - trying again")
		end
		return nil
	end
	image:WritePixelsBuffer(Vector2.zero, Vector2.new(picture.w, picture.h), picture.pixels)
	if cached then
		cached.image:Destroy() -- Minecraft sent a different picture for the same key (resource pack)
	end
	failedAt[cacheKey] = nil
	local content = Content.fromObject(image)
	cache[cacheKey] = { image = image, content = content, source = source }
	return content
end

-- Moving pictures (water, lava - Minecraft's .png.mcmeta): one picture per texture key, its frames written into it
-- one after the other (every Texture with that picture moves along)
local animations = {} -- cache key -> {texture, frames = {buffer}, shown = frame index}
local function frameOf(texture: any, index: number): any
	-- (texture.h is one frame; the pixels hold all of them one below the other)
	local strip = { w = texture.w, h = texture.h * texture.frames, pixels = texture.pixels }
	return Images.crop(strip :: any, 0, index * texture.h, texture.w, texture.h)
end

local function worldContent(key: any, turn: number?): Content?
	local texture = type(key) == "string" and assets and assets.textures and assets.textures[key]
	if not texture then
		return nil
	end
	if texture.frames and texture.frames > 1 and ((turn or 0) // 90) % 4 == 0 then
		local cacheKey = "anim:" .. tostring(key)
		local content = makeImage(cacheKey, texture, function()
			return Images.upscale(frameOf(texture, 0), ANIMATED_SCALE)
		end)
		local entry = animations[cacheKey]
		if content and (not entry or entry.texture ~= texture) then
			animations[cacheKey] = { texture = texture, frames = {}, shown = 0 }
		end
		return content
	end
	local quarter = ((turn or 0) // 90) % 4
	return makeImage("world:" .. tostring(key) .. (if quarter ~= 0 then "@" .. quarter else ""), texture,
		function()
			return Images.upscale(if quarter ~= 0 then Images.turn(texture, quarter * 90) else texture, TEXTURE_SCALE)
		end)
end

-- Minecraft's animation clock: every frametime ticks the next frame (in the order of the .mcmeta, if it has one)
RunService.Heartbeat:Connect(function()
	local tick = math.floor(os.clock() * 20)
	for cacheKey, entry in pairs(animations) do
		local texture = entry.texture
		local cached = cache[cacheKey]
		if not cached or not cached.image then
			continue
		end
		local order = texture.order
		local step = tick // texture.frametime
		local index = if order and #order > 0 then order[step % #order + 1] else step % texture.frames
		if index ~= entry.shown and index < texture.frames then
			entry.shown = index
			local frame = entry.frames[index]
			if not frame then
				frame = Images.upscale(frameOf(texture, index), ANIMATED_SCALE)
				entry.frames[index] = frame
			end
			pcall(function()
				cached.image:WritePixelsBuffer(Vector2.zero, Vector2.new(frame.w, frame.h), frame.pixels)
			end)
		end
	end
end)

local function guiPicture(key: string): Content?
	local texture = assets and assets.textures and assets.textures[key]
	if not texture then
		return nil
	end
	return makeImage("gui:" .. key, buffer.tostring(texture.pixels), function()
		return texture
	end)
end

-- the sun and the moon: Minecraft adds them onto the sky (black = nothing) - see Images.additive
local function glowPicture(key: string): Content?
	local texture = assets and assets.textures and assets.textures[key]
	if not texture then
		return nil
	end
	return makeImage("glow:" .. key, buffer.tostring(texture.pixels), function()
		return Images.additive(texture)
	end)
end

-- An item's icon (like Minecraft's inventory): a flat picture (redstone, doors, tools) or its block / model in 3D
local function iconContent(id: string?): Content?
	local item = itemInfo(id)
	if not id or not item then
		return nil
	end
	local textures = assets and assets.textures or {}
	if type(item.icon) == "string" and textures[item.icon] then
		local picture = textures[item.icon]
		return makeImage("icon:" .. id, item.icon, function()
			return Images.upscale(picture, math.max(1, ICON_SIZE // math.max(picture.w, 1)))
		end)
	end
	local look = assets and assets.blocks and (assets.blocks[item.look or ""] or assets.blocks[item.block or ""])
	if look and look.cube then
		local faces = look.faces or {}
		local top, north, east = textures[faces.up], textures[faces.north], textures[faces.east]
		if top and north and east then
			return makeImage("icon:" .. id, faces.up .. faces.north .. faces.east, function()
				return Images.blockIcon(top, north, east, ICON_SIZE)
			end)
		end
	elseif look and look.model then
		local boxes = {}
		local source = ""
		for _, piece in ipairs(look.parts or {}) do
			if type(piece.b) == "table" then
				local faces = {}
				for direction, key in pairs(piece.f or {}) do
					faces[direction] = textures[key]
					source ..= key
				end
				table.insert(boxes, { from = { piece.b[1], piece.b[2], piece.b[3] }, to = { piece.b[4], piece.b[5], piece.b[6] },
					faces = faces })
			end
		end
		if #boxes > 0 then
			return makeImage("icon:" .. id, source, function()
				return Images.modelIcon(boxes, ICON_SIZE)
			end)
		end
	end
	return makeImage("icon:" .. id, "plain", function()
		return Images.solid(16, 16, 120, 160, 80) -- a plain square when Minecraft sent no pictures
	end)
end

-- Skins: the server keeps the 64x64 pixels per skin key, every face of a body part shows its part of it
local skins = {} -- skin key -> picture | false (asked, none)
local skinAsking = {}
local SKIN_SCALE = 4
local retryWaiting -- below

local function skinPicture(key: string)
	if skins[key] ~= nil then
		return skins[key] or nil
	end
	if not skinAsking[key] then
		skinAsking[key] = true
		task.spawn(function()
			local ok, result = pcall(function()
				return getSkin:InvokeServer(key)
			end)
			if ok and type(result) == "table" and typeof(result.pixels) == "buffer" then
				skins[key] = result
			else
				task.wait(5) -- try again later
			end
			skinAsking[key] = nil
			retryWaiting()
		end)
	end
	return nil
end

local function skinContent(key: string, region: string): Content?
	local picture = skinPicture(key)
	if not picture then
		return nil
	end
	local x, y, w, h = string.match(region, "^(%d+),(%d+),(%d+),(%d+)$")
	if not x then
		return nil
	end
	return makeImage("skin:" .. key .. ":" .. region, key, function()
		return Images.upscale(Images.crop(picture, tonumber(x) :: number, tonumber(y) :: number, tonumber(w) :: number,
			tonumber(h) :: number), SKIN_SCALE)
	end)
end

-- Keeping the pictures on screen: when Textures go away (a block is placed / broken, the server builds that part of
-- the world new), Roblox sometimes stops drawing that picture on ALL blocks of the kind (they turn grey until the next
-- change). So: after Textures went away, every block of that kind gets its picture once more (next frame), and a
-- hidden part keeps one Texture per picture for good.
local shownBy = {} -- world texture key -> {Texture -> true} (weak)
local holders = {} -- world texture key -> Texture on the hidden part
local holderPart: Part? = nil
local lost = {} -- world texture key -> true: Textures with this picture went away
--[[
	The refresh costs one property write per Texture of that kind - with a real world (tens of thousands of Textures)
	and chunks going away all the time (flying, a portal), doing it at once every frame made Roblox stutter badly. So:
	the kinds that lost Textures are collected for REFRESH_EVERY seconds, their Textures go into a queue, and the queue
	is worked off with at most REFRESH_BUDGET seconds per frame (a grey block is back within a moment).
]]
local REFRESH_EVERY = 0.5
local REFRESH_BUDGET = 0.0015
local refreshQueue: { Texture } = {}
local refreshQueued = setmetatable({}, { __mode = "k" }) -- Texture -> true (in the queue)
local refreshPassAt = 0
local pixelated: boolean? = nil -- does this Roblox know Texture.ResampleMode? (asked once)
local function setPixelated(texture: Texture)
	if pixelated == nil then
		pixelated = pcall(function()
			texture.ResampleMode = Enum.ResamplerMode.Pixelated
		end)
	elseif pixelated then
		texture.ResampleMode = Enum.ResamplerMode.Pixelated
	end
end

local function hold(key: string, content: Content)
	local camera = workspace.CurrentCamera
	if not camera then
		return
	end
	if not holderPart or not holderPart.Parent then
		local part = Instance.new("Part")
		part.Name = "MinecraftTextureHolder"
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Transparency = 1
		part.Size = Vector3.one * 0.05
		part.CFrame = CFrame.new(0, -500, 0)
		part.Parent = camera -- only here on this client
		holderPart = part
		table.clear(holders)
	end
	if not holders[key] then
		local texture = Instance.new("Texture")
		texture.Name = key
		texture.Parent = holderPart
		holders[key] = texture
	end
	if holders[key].TextureContent ~= content then
		holders[key].TextureContent = content
	end
end

local function turnOf(texture: Texture): number
	-- (the server's MinecraftWorldConfig TopTurn / BottomTurn, or "/drehen oben 90" live)
	if texture.Face == Enum.NormalId.Top then
		return tonumber(ReplicatedStorage:GetAttribute("McTopTurn")) or TOP_TURN
	elseif texture.Face == Enum.NormalId.Bottom then
		return tonumber(ReplicatedStorage:GetAttribute("McBottomTurn")) or BOTTOM_TURN
	end
	return 0
end

local function showAgain(key: string)
	local plain = worldContent(key)
	if not plain then
		return
	end
	for texture in pairs(shownBy[key] or {}) do
		if not refreshQueued[texture] then
			refreshQueued[texture] = true
			table.insert(refreshQueue, texture) -- (worked off a bit per frame: see the Heartbeat below)
		end
	end
	local holder = holders[key]
	if holder then
		holder.TextureContent = Content.none
		holder.TextureContent = plain
	end
end

local function refreshSome()
	local started = os.clock()
	while #refreshQueue > 0 and os.clock() - started < REFRESH_BUDGET do
		local texture = table.remove(refreshQueue) :: Texture
		refreshQueued[texture] = nil
		if texture.Parent then
			local key = texture:GetAttribute("McTexture")
			local content = if type(key) == "string" then worldContent(key, turnOf(texture)) else nil
			if content then
				texture.TextureContent = Content.none
				texture.TextureContent = content
			end
		end
	end
end

local function applyTexture(texture: Texture)
	local content = nil
	local region = texture:GetAttribute("McSkinFace")
	if type(region) == "string" then
		local model = texture:FindFirstAncestorOfClass("Model")
		local key = model and model:GetAttribute("McSkin")
		if type(key) ~= "string" then
			waiting[texture] = nil -- no skin yet: the model's colour; McSkin coming brings it
			return
		end
		content = skinContent(key :: string, region)
	else
		local key = texture:GetAttribute("McTexture")
		content = worldContent(key, turnOf(texture))
		if content and type(key) == "string" then
			shownBy[key] = shownBy[key] or setmetatable({}, { __mode = "k" })
			shownBy[key][texture] = true
			hold(key, content)
		end
	end
	if content then
		texture.TextureContent = content
		setPixelated(texture)
		waiting[texture] = nil
	else
		waiting[texture] = true
	end
end

local function applyModel(model: Instance)
	for _, item in ipairs(model:GetDescendants()) do
		if item:IsA("Texture") and item:GetAttribute("McSkinFace") then
			applyTexture(item)
		end
	end
end

local function applyAllTextures()
	for _, item in ipairs(workspace:GetDescendants()) do
		if item:IsA("Texture") and (item:GetAttribute("McTexture") or item:GetAttribute("McSkinFace")) then
			applyTexture(item)
		end
	end
end

retryWaiting = function()
	for texture in pairs(waiting) do
		if texture.Parent then
			applyTexture(texture)
		else
			waiting[texture] = nil
		end
	end
end

local function watchModel(model: Model)
	model:GetAttributeChangedSignal("McSkin"):Connect(function()
		applyModel(model)
	end)
end

workspace.DescendantRemoving:Connect(function(item)
	if item:IsA("Texture") then
		local key = item:GetAttribute("McTexture")
		if type(key) == "string" then
			lost[key] = true
		end
	end
end)
RunService.Heartbeat:Connect(function()
	local now = os.clock()
	if next(lost) ~= nil and now - refreshPassAt >= REFRESH_EVERY then
		refreshPassAt = now
		local keys = lost
		lost = {}
		for key in pairs(keys) do
			showAgain(key)
		end
	end
	if #refreshQueue > 0 then
		refreshSome()
	end
end)

workspace.DescendantAdded:Connect(function(item)
	if item:IsA("Texture") then
		if item:GetAttribute("McTexture") or item:GetAttribute("McSkinFace") then
			applyTexture(item)
		end
		if item:GetAttribute("McSkinFace") then
			item:GetAttributeChangedSignal("McSkinFace"):Connect(function()
				applyTexture(item) -- slim / wide arms: another part of the skin
			end)
		end
	elseif item:IsA("Model") and item:GetAttribute("McSkinUser") ~= nil then
		watchModel(item)
	end
end)
for _, item in ipairs(workspace:GetDescendants()) do
	if item:IsA("Model") and item:GetAttribute("McSkinUser") ~= nil then
		watchModel(item)
	end
end
-- endregion

-- region GUI
pcall(function()
	StarterGui:SetCoreGuiEnabled(Enum.CoreGuiType.Backpack, false) -- our hotbar instead of Roblox's
	StarterGui:SetCoreGuiEnabled(Enum.CoreGuiType.Health, false) -- our hearts instead of Roblox's bar
end)

local screen = Instance.new("ScreenGui")
screen.Name = "MinecraftHud"
screen.ResetOnSpawn = false
screen.IgnoreGuiInset = true
screen.DisplayOrder = 5
screen.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
screen.Parent = player:WaitForChild("PlayerGui")

-- Minecraft's GUI scale: everything is built in Minecraft pixels and scaled up
local function guiScale()
	local size = workspace.CurrentCamera and workspace.CurrentCamera.ViewportSize or Vector2.new(1280, 720)
	return if size.Y >= 900 then 3 elseif size.Y >= 500 then 2 else 1
end
local scales = {}
local function scaled(frame: GuiObject)
	local scale = Instance.new("UIScale")
	scale.Scale = guiScale()
	scale.Parent = frame
	table.insert(scales, scale)
end
local function onViewport()
	for _, scale in ipairs(scales) do
		scale.Scale = guiScale()
	end
end

local function image(parent: Instance, name: string, x: number, y: number, w: number, h: number, z: number): ImageLabel
	local label = Instance.new("ImageLabel")
	label.Name = name
	label.BackgroundTransparency = 1
	label.Position = UDim2.fromOffset(x, y)
	label.Size = UDim2.fromOffset(w, h)
	label.ZIndex = z
	label.ResampleMode = Enum.ResamplerMode.Pixelated
	label.Parent = parent
	return label
end

local function setPicture(label: ImageLabel, content: Content?)
	label.ImageContent = content or Content.none
end

local function gui(name: string): Content?
	local key = assets and assets.gui and assets.gui[name]
	return if key then guiPicture(key) else nil
end

-- A slot: the icon, the count (bottom right, Minecraft only shows it above 1), the durability bar of tools
type SlotView = { icon: ImageLabel, count: TextLabel, bar: Frame, fill: Frame }
local function slotView(parent: Instance, name: string, x: number, y: number, z: number): SlotView
	local icon = image(parent, name, x, y, 16, 16, z)
	icon.ResampleMode = Enum.ResamplerMode.Default -- the icons are bigger pictures: smooth
	local count = Instance.new("TextLabel")
	count.Name = "Count"
	count.BackgroundTransparency = 1
	count.Position = UDim2.fromOffset(x, y + 1)
	count.Size = UDim2.fromOffset(17, 16)
	count.TextXAlignment = Enum.TextXAlignment.Right
	count.TextYAlignment = Enum.TextYAlignment.Bottom
	count.Font = Enum.Font.Arcade
	count.TextSize = 9
	count.TextColor3 = Color3.new(1, 1, 1)
	count.TextStrokeTransparency = 0.3
	count.ZIndex = z + 2
	count.Text = ""
	count.Parent = parent
	local bar = Instance.new("Frame")
	bar.Name = "Durability"
	bar.BorderSizePixel = 0
	bar.BackgroundColor3 = Color3.new(0, 0, 0)
	bar.Position = UDim2.fromOffset(x + 2, y + 13)
	bar.Size = UDim2.fromOffset(13, 2)
	bar.ZIndex = z + 1
	bar.Visible = false
	bar.Parent = parent
	local fill = Instance.new("Frame")
	fill.BorderSizePixel = 0
	fill.Size = UDim2.fromOffset(13, 1)
	fill.ZIndex = z + 1
	fill.Parent = bar
	return { icon = icon, count = count, bar = bar, fill = fill }
end

local function showStack(view: SlotView, stack: any)
	local id = if type(stack) == "table" then stack.id else nil
	setPicture(view.icon, iconContent(id))
	local n = if type(stack) == "table" then tonumber(stack.n) or 1 else 0
	view.count.Text = if n > 1 then tostring(n) else ""
	local bar = if type(stack) == "table" then tonumber(stack.bar) else nil
	view.bar.Visible = bar ~= nil
	if bar then
		view.fill.Size = UDim2.fromOffset(math.max(1, math.floor(13 * bar + 0.5)), 1)
		view.fill.BackgroundColor3 = Color3.fromHSV(bar / 3, 1, 1) -- green -> red like Minecraft
	end
end

-- Hotbar: 182 x 22 Minecraft pixels at the bottom
local hotbar = Instance.new("Frame")
hotbar.Name = "Hotbar"
hotbar.AnchorPoint = Vector2.new(0.5, 1)
hotbar.Position = UDim2.new(0.5, 0, 1, 0)
hotbar.Size = UDim2.fromOffset(182, 22)
hotbar.BackgroundTransparency = 1
hotbar.Parent = screen
scaled(hotbar)
local hotbarBack = image(hotbar, "Background", 0, 0, 182, 22, 1)
local hotbarSlots: { SlotView } = {}
for slot = 1, 9 do
	hotbarSlots[slot] = slotView(hotbar, "Slot" .. slot, 3 + (slot - 1) * 20, 3, 2)
end
local selection = image(hotbar, "Selection", -1, -1, 24, 23, 5)
local itemName = Instance.new("TextLabel")
itemName.Name = "ItemName"
itemName.BackgroundTransparency = 1
itemName.AnchorPoint = Vector2.new(0.5, 1)
itemName.Position = UDim2.new(0.5, 0, 0, -36) -- above the hearts (and the armor row)
itemName.Size = UDim2.fromOffset(182, 10)
itemName.Font = Enum.Font.Arcade
itemName.TextSize = 9
itemName.TextColor3 = Color3.new(1, 1, 1)
itemName.TextStrokeTransparency = 0.6
itemName.TextTransparency = 1
itemName.Parent = hotbar
local nameShownAt = -math.huge

-- The inventory windows over a darker screen; a click on the dark part = outside the window
local dim = Instance.new("TextButton")
dim.Name = "Inventory"
dim.Text = ""
dim.AutoButtonColor = false
dim.BackgroundColor3 = Color3.new(0, 0, 0)
dim.BackgroundTransparency = 0.45
dim.Size = UDim2.fromScale(1, 1)
dim.Visible = false
dim.ZIndex = 10
dim.Parent = screen

local function newWindow(name: string, w: number, h: number): (Frame, ImageLabel)
	local frame = Instance.new("Frame")
	frame.Name = name
	frame.AnchorPoint = Vector2.new(0.5, 0.5)
	frame.Position = UDim2.fromScale(0.5, 0.5)
	frame.Size = UDim2.fromOffset(w, h)
	frame.BackgroundTransparency = 1
	frame.ZIndex = 11
	frame.Parent = dim
	scaled(frame)
	local back = image(frame, "Background", 0, 0, w, h, 11)
	-- clicks on the window itself (not on a slot) are not "outside"
	local catcher = Instance.new("TextButton")
	catcher.Text = ""
	catcher.BackgroundTransparency = 1
	catcher.Size = UDim2.fromScale(1, 1)
	catcher.ZIndex = 12
	catcher.Parent = frame
	return frame, back
end

local window, windowBack = newWindow("Window", 176, 166) -- Minecraft's inventory (survival / adventure)
local creative, creativeBack = newWindow("Creative", 195, 136) -- Minecraft's creative inventory, items tab
-- an open chest / furnace / crafting table ...: Minecraft's own menu (its slots where Minecraft draws them)
local container, containerBack = newWindow("Container", 176, 166)

local preview = Instance.new("ViewportFrame") -- the player in the black box, like in Minecraft
preview.Name = "Player"
preview.BackgroundTransparency = 1
preview.Position = UDim2.fromOffset(26, 8)
preview.Size = UDim2.fromOffset(49, 70)
preview.ZIndex = 13
preview.Parent = window

local highlight = Instance.new("Frame")
highlight.Name = "Highlight"
highlight.BackgroundColor3 = Color3.new(1, 1, 1)
highlight.BackgroundTransparency = 0.55
highlight.BorderSizePixel = 0
highlight.Size = UDim2.fromOffset(16, 16)
highlight.Visible = false
highlight.ZIndex = 17
local hovered: any = nil
local hoverName = Instance.new("TextLabel") -- the item name next to the mouse (Minecraft's tooltip)
hoverName.Name = "Tooltip"
hoverName.BackgroundColor3 = Color3.fromRGB(16, 0, 16)
hoverName.BackgroundTransparency = 0.1
hoverName.BorderSizePixel = 0
hoverName.Font = Enum.Font.Arcade
hoverName.TextSize = 18
hoverName.TextColor3 = Color3.new(1, 1, 1)
hoverName.AutomaticSize = Enum.AutomaticSize.X
hoverName.Size = UDim2.fromOffset(0, 22)
hoverName.Visible = false
hoverName.ZIndex = 40
hoverName.Parent = screen

-- where Minecraft's menu slots are in the inventory picture
local function survivalSlotPosition(menuSlot: number): (number, number)
	if menuSlot == 0 then
		return 154, 28 -- crafting result
	elseif menuSlot <= 4 then
		local index = menuSlot - 1
		return 98 + (index % 2) * 18, 18 + (index // 2) * 18 -- 2x2 crafting grid
	elseif menuSlot <= 8 then
		return 8, 8 + (menuSlot - 5) * 18 -- armour
	elseif menuSlot <= 35 then
		local index = menuSlot - 9
		return 8 + (index % 9) * 18, 84 + (index // 9) * 18
	elseif menuSlot <= 44 then
		return 8 + (menuSlot - 36) * 18, 142 -- hotbar row
	end
	return 77, 62 -- offhand
end

local refresh -- defined below
local clickSurvival -- below
local clickCreativeItem -- below
local clickCreativeHotbar -- below

local function hoverable(button: GuiButton, parent: Instance, x: number, y: number, what: () -> any)
	button.MouseEnter:Connect(function()
		hovered = what
		highlight.Parent = parent
		highlight.Position = UDim2.fromOffset(x, y)
		highlight.Visible = true
	end)
	button.MouseLeave:Connect(function()
		if hovered == what then
			hovered = nil
			highlight.Visible = false
		end
	end)
end

local function slotButton(parent: Instance, name: string, x: number, y: number): TextButton
	local button = Instance.new("TextButton")
	button.Name = name
	button.Text = ""
	button.BackgroundTransparency = 1
	button.Position = UDim2.fromOffset(x - 1, y - 1)
	button.Size = UDim2.fromOffset(18, 18)
	button.ZIndex = 18
	button.Parent = parent
	return button
end

local survivalSlots: { SlotView } = {}
for menuSlot = 0, 45 do
	local x, y = survivalSlotPosition(menuSlot)
	survivalSlots[menuSlot + 1] = slotView(window, "Slot" .. menuSlot, x, y, 14)
	local button = slotButton(window, "Click" .. menuSlot, x, y)
	button.MouseButton1Click:Connect(function()
		clickSurvival(menuSlot, 0)
	end)
	button.MouseButton2Click:Connect(function()
		clickSurvival(menuSlot, 1)
	end)
	hoverable(button, window, x, y, function()
		return stackAt(menuSlot)
	end)
end

-- creative: 9 x 5 items (scrolling), the hotbar row below, the scroll bar on the right, Minecraft's tabs above and
-- below (Building Blocks, Colored Blocks, Natural, Functional, Redstone | Search; Tools, Combat, Food, Ingredients,
-- Spawn Eggs | Survival Inventory) - the tabs + their items come from Minecraft itself (mod: Assets.creativeTabs)
local CREATIVE_ROWS = 5
local creativeScroll = 0 -- first row shown
local creativeTab = "first" -- id of the chosen Minecraft tab, "search", or "first" (the first tab / all items)
local searchText = ""
local itemIndexFor: any = nil -- assets.items -> {id -> item}
local itemIndex: { [string]: any } = {}
local listCache = { key = "", list = {} :: { any } }

local function creativeList(): { any }
	local items = assets and assets.items or {}
	local tabList = assets and assets.tabs or {}
	if itemIndexFor ~= items then
		itemIndexFor = items
		itemIndex = {}
		for _, item in ipairs(items) do
			itemIndex[item.id] = item
		end
	end
	local known = 0
	for _ in pairs(assets and assets.itemsById or {}) do
		known += 1
	end
	local key = creativeTab .. "|" .. searchText .. "|" .. tostring(items) .. "|" .. tostring(tabList) .. "|" .. known
	if listCache.key == key then
		return listCache.list
	end
	local list = items
	if creativeTab == "search" then
		-- every item of every tab (else the list from the start), by name or id
		local needle = string.lower(searchText)
		list = {}
		local pool = items
		if #tabList > 0 then
			pool = {}
			local seen = {}
			for _, tab in ipairs(tabList) do
				for _, id in ipairs(tab.items or {}) do
					local item = itemIndex[id] or (assets.itemsById and assets.itemsById[id])
					if item and not seen[id] then
						seen[id] = true
						table.insert(pool, item)
					end
				end
			end
		end
		for _, item in ipairs(pool) do
			if needle == "" or string.find(string.lower(tostring(item.name or "")), needle, 1, true)
				or string.find(item.id, needle, 1, true) then
				table.insert(list, item)
			end
		end
	else
		local chosen = nil
		for _, tab in ipairs(tabList) do
			if tab.id == creativeTab or (creativeTab == "first" and chosen == nil) then
				chosen = tab
			end
		end
		if chosen then
			list = {}
			for _, id in ipairs(chosen.items or {}) do
				local item = itemIndex[id] or (assets.itemsById and assets.itemsById[id])
				if item then
					table.insert(list, item)
				end
			end
		end
	end
	listCache.key = key
	listCache.list = list
	return list
end
local creativeItems: { SlotView } = {}
for index = 0, 9 * CREATIVE_ROWS - 1 do
	local x, y = 9 + (index % 9) * 18, 18 + (index // 9) * 18
	creativeItems[index + 1] = slotView(creative, "Item" .. index, x, y, 14)
	local button = slotButton(creative, "ClickItem" .. index, x, y)
	button.MouseButton1Click:Connect(function()
		clickCreativeItem(index, 0)
	end)
	button.MouseButton2Click:Connect(function()
		clickCreativeItem(index, 1)
	end)
	hoverable(button, creative, x, y, function()
		local item = creativeList()[creativeScroll * 9 + index + 1]
		return if item then { id = item.id, n = 1, name = item.name } else nil
	end)
end
local creativeHotbar: { SlotView } = {}
for slot = 1, 9 do
	local x, y = 9 + (slot - 1) * 18, 112
	creativeHotbar[slot] = slotView(creative, "Hotbar" .. slot, x, y, 14)
	local button = slotButton(creative, "ClickHotbar" .. slot, x, y)
	button.MouseButton1Click:Connect(function()
		clickCreativeHotbar(slot, 0)
	end)
	button.MouseButton2Click:Connect(function()
		clickCreativeHotbar(slot, 1)
	end)
	hoverable(button, creative, x, y, function()
		return hotbarStack(slot)
	end)
end
local scroller = image(creative, "Scroller", 175, 18, 12, 15, 15)

-- the tabs (made again when Minecraft's tab list comes): {frame, icon, view, tab, row = "top" | "bottom", column}
local tabs = {}
local setView -- below
local searchBox = Instance.new("TextBox") -- Minecraft's search field (search tab)
searchBox.Name = "Search"
searchBox.BackgroundTransparency = 1
searchBox.Position = UDim2.fromOffset(82, 6)
searchBox.Size = UDim2.fromOffset(89, 9)
searchBox.Font = Enum.Font.Arcade
searchBox.TextSize = 8
searchBox.TextColor3 = Color3.new(1, 1, 1)
searchBox.TextXAlignment = Enum.TextXAlignment.Left
searchBox.ClearTextOnFocus = false
searchBox.PlaceholderText = ""
searchBox.Text = ""
searchBox.Visible = false
searchBox.ZIndex = 19
searchBox.Parent = creative
local tabTitle = Instance.new("TextLabel") -- the tab's name at the top left (Minecraft draws it there)
tabTitle.Name = "Title"
tabTitle.BackgroundTransparency = 1
tabTitle.Position = UDim2.fromOffset(8, 5)
tabTitle.Size = UDim2.fromOffset(100, 9)
tabTitle.Font = Enum.Font.Arcade
tabTitle.TextSize = 8
tabTitle.TextColor3 = Color3.fromRGB(64, 64, 64)
tabTitle.TextXAlignment = Enum.TextXAlignment.Left
tabTitle.Text = ""
tabTitle.ZIndex = 13
tabTitle.Parent = creative

local function chooseTab(entry)
	if entry.view == "survival" then
		setView("survival")
		return
	end
	creativeTab = entry.tab
	creativeScroll = 0
	setView("creative")
	refresh()
	if entry.tab == "search" then
		pcall(function()
			searchBox:CaptureFocus()
		end)
	end
end

local function rebuildTabs()
	for _, entry in ipairs(tabs) do
		entry.frame:Destroy()
	end
	table.clear(tabs)
	local list = {}
	local tabList = assets and assets.tabs or {}
	if #tabList == 0 then
		-- an older mod: one tab with all items + the inventory
		table.insert(list, { view = "creative", tab = "first", row = "top", column = 0, iconItem = "minecraft:grass_block", name = "" })
		table.insert(list, { view = "survival", row = "top", column = 1, iconItem = "minecraft:crafting_table", name = "" })
	else
		for index, tab in ipairs(tabList) do
			local i = index - 1
			table.insert(list, { view = "creative", tab = tab.id, row = if i < 5 then "top" else "bottom",
				column = i % 5, iconItem = tab.icon, name = tab.name })
		end
		table.insert(list, { view = "creative", tab = "search", row = "top", column = 6, iconItem = "minecraft:compass",
			name = "Suche" })
		table.insert(list, { view = "survival", row = "bottom", column = 6, iconItem = "minecraft:chest", name = "" })
	end
	for _, entry in ipairs(list) do
		local tab = image(dim, "Tab", 0, 0, 26, 32, 12)
		scaled(tab)
		local tabIcon = image(tab, "Icon", 5, if entry.row == "top" then 9 else 7, 16, 16, 13)
		tabIcon.ResampleMode = Enum.ResamplerMode.Default
		local button = Instance.new("TextButton")
		button.Text = ""
		button.BackgroundTransparency = 1
		button.Size = UDim2.fromScale(1, 1)
		button.ZIndex = 14
		button.Parent = tab
		button.MouseButton1Click:Connect(function()
			chooseTab(entry)
		end)
		button.MouseEnter:Connect(function()
			if entry.name ~= "" then
				hovered = function()
					return { id = entry.iconItem, n = 1, name = entry.name }
				end
			end
		end)
		button.MouseLeave:Connect(function()
			hovered = nil
		end)
		entry.frame = tab
		entry.icon = tabIcon
		table.insert(tabs, entry)
	end
	local known = creativeTab == "search" or creativeTab == "first"
	for _, tab in ipairs(tabList) do
		if tab.id == creativeTab then
			known = true
		end
	end
	if not known or (creativeTab == "first" and #tabList > 0) then
		creativeTab = if #tabList > 0 then (tabList[1].id :: string) else "first"
	end
end
rebuildTabs()

searchBox:GetPropertyChangedSignal("Text"):Connect(function()
	if searchBox.Text ~= searchText then
		searchText = searchBox.Text
		creativeScroll = 0
		refresh()
	end
end)

-- the item on the mouse while moving it around
local cursor = slotView(screen, "CursorItem", 0, 0, 30)
local cursorFrame = Instance.new("Frame")
cursorFrame.Name = "Cursor"
cursorFrame.BackgroundTransparency = 1
cursorFrame.Size = UDim2.fromOffset(16, 16)
cursorFrame.AnchorPoint = Vector2.new(0.5, 0.5)
cursorFrame.ZIndex = 30
cursorFrame.Parent = screen
scaled(cursorFrame)
for _, item in ipairs({ cursor.icon, cursor.count, cursor.bar }) do
	item.Parent = cursorFrame
end
cursor.icon.Position = UDim2.fromOffset(0, 0)
cursor.count.Position = UDim2.fromOffset(0, 1)
cursor.bar.Position = UDim2.fromOffset(2, 13)

-- region container window (state.menu from Minecraft: {type, title, slots = {{x, y, stack}}, burn?, cook?})
local containerSlots = {} -- index -> {view, button, index}
local containerTitle = Instance.new("TextLabel")
containerTitle.Name = "Title"
containerTitle.BackgroundTransparency = 1
containerTitle.Position = UDim2.fromOffset(8, 5)
containerTitle.Size = UDim2.fromOffset(160, 9)
containerTitle.Font = Enum.Font.Arcade
containerTitle.TextSize = 8
containerTitle.TextColor3 = Color3.fromRGB(64, 64, 64)
containerTitle.TextXAlignment = Enum.TextXAlignment.Left
containerTitle.ZIndex = 13
containerTitle.Parent = container
local containerInventory = Instance.new("TextLabel") -- Minecraft: "Inventory" above the player's slots
containerInventory.Name = "InventoryTitle"
containerInventory.BackgroundTransparency = 1
containerInventory.Size = UDim2.fromOffset(160, 9)
containerInventory.Font = Enum.Font.Arcade
containerInventory.TextSize = 8
containerInventory.TextColor3 = Color3.fromRGB(64, 64, 64)
containerInventory.TextXAlignment = Enum.TextXAlignment.Left
containerInventory.Text = "Inventar"
containerInventory.ZIndex = 13
containerInventory.Parent = container
local furnaceFire = Instance.new("Frame") -- the fire fills from the bottom, the arrow from the left
furnaceFire.Name = "Fire"
furnaceFire.BackgroundTransparency = 1
furnaceFire.ClipsDescendants = true
furnaceFire.ZIndex = 13
furnaceFire.Parent = container
local furnaceFireImage = image(furnaceFire, "Image", 0, 0, 14, 14, 13)
local furnaceArrow = Instance.new("Frame")
furnaceArrow.Name = "Arrow"
furnaceArrow.BackgroundTransparency = 1
furnaceArrow.ClipsDescendants = true
furnaceArrow.ZIndex = 13
furnaceArrow.Parent = container
local furnaceArrowImage = image(furnaceArrow, "Image", 0, 0, 24, 16, 13)
local CONTAINER_SIZES = { hopper = { 176, 133 }, beacon = { 230, 219 }, merchant = { 276, 166 } }

local function containerSize(menu: any): (number, number)
	local rows = string.match(tostring(menu.type), "^generic_9x(%d)$")
	if rows then
		return 176, 114 + tonumber(rows) :: number * 18
	end
	local size = CONTAINER_SIZES[menu.type]
	return if size then size[1] else 176, if size then size[2] else 166
end

local function clickContainer(index: number, button: number)
	if gameMode() == "spectator" then
		return
	end
	local shift = UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) or UserInputService:IsKeyDown(Enum.KeyCode.RightShift)
	inventoryRemote:FireServer("click", index, button, shift, true)
end

local enchantButtons: { TextButton } = {}
local tradeRows: { any } = {}
local anvilName: TextBox? = nil
local optionButtons: { TextButton } = {}
local optionViews: { any } = {}
local anvilCost: TextLabel? = nil
local function refreshContainer()
	local menu = state.menu
	if type(menu) ~= "table" or type(menu.slots) ~= "table" then
		return
	end
	local width, height = containerSize(menu)
	container.Size = UDim2.fromOffset(width, height)
	containerBack.Size = UDim2.fromOffset(width, height)
	local picture = gui("container_" .. tostring(menu.type))
	setPicture(containerBack, picture)
	containerBack.BackgroundTransparency = if picture then 1 else 0
	containerBack.BackgroundColor3 = Color3.fromRGB(198, 198, 198)
	containerTitle.Text = tostring(menu.title or "")
	containerInventory.Position = UDim2.fromOffset(8, height - 94 + 1)
	containerInventory.Visible = menu.type ~= "beacon" and menu.type ~= "merchant"
	for index, slot in ipairs(menu.slots) do
		local entry = containerSlots[index]
		local x, y = tonumber(slot[1]) or 0, tonumber(slot[2]) or 0
		if not entry then
			local view = slotView(container, "Slot" .. index, x, y, 14)
			local button = slotButton(container, "Click" .. index, x, y)
			local menuIndex = index - 1
			button.MouseButton1Click:Connect(function()
				clickContainer(menuIndex, 0)
			end)
			button.MouseButton2Click:Connect(function()
				clickContainer(menuIndex, 1)
			end)
			entry = { view = view, button = button }
			hoverable(button, container, x, y, function()
				local current = state.menu
				local stack = type(current) == "table" and type(current.slots) == "table" and current.slots[index]
				return if type(stack) == "table" and type(stack[3]) == "table" then stack[3] else nil
			end)
			containerSlots[index] = entry
		end
		entry.view.icon.Position = UDim2.fromOffset(x, y)
		entry.button.Position = UDim2.fromOffset(x - 1, y - 1)
		entry.button.Visible = true
		showStack(entry.view, if type(slot[3]) == "table" then slot[3] else nil)
	end
	for index = #menu.slots + 1, #containerSlots do
		containerSlots[index].button.Visible = false
		showStack(containerSlots[index].view, nil)
	end
	-- the stonecutter's choices (their items) / the loom's patterns (their names): Minecraft's buttons
	local options = if type(menu.options) == "table" then menu.options elseif type(menu.patterns) == "table" then menu.patterns else nil
	local loom = type(menu.patterns) == "table"
	for i = 1, 16 do
		local button = optionButtons[i]
		if not button and options then
			local made = Instance.new("TextButton")
			made.Name = "Option" .. i
			made.AutoButtonColor = true
			made.BorderSizePixel = 0
			made.Font = Enum.Font.Arcade
			made.TextSize = 5
			made.TextWrapped = true
			made.ZIndex = 14
			made.Parent = container
			local index = i - 1
			made.MouseButton1Click:Connect(function()
				inventoryRemote:FireServer("button", index)
			end)
			optionButtons[i] = made
			optionViews[i] = slotView(made, "Icon", 0, 1, 15)
			button = made
		end
		if button then
			local option = options and options[i]
			button.Visible = option ~= nil
			if option ~= nil then
				local column, row = (i - 1) % 4, (i - 1) // 4
				if loom then
					button.Position = UDim2.fromOffset(60 + column * 14, 13 + row * 14)
					button.Size = UDim2.fromOffset(14, 14)
					button.Text = string.upper(string.sub(string.gsub(tostring(option), "_", " "), 1, 6))
					showStack(optionViews[i], nil)
				else
					button.Position = UDim2.fromOffset(52 + column * 16, 14 + row * 18)
					button.Size = UDim2.fromOffset(16, 18)
					button.Text = ""
					showStack(optionViews[i], if type(option) == "table" then option else nil)
				end
				local chosen = tonumber(menu.selected) == i - 1
				button.BackgroundColor3 = if chosen then Color3.fromRGB(120, 170, 120) else Color3.fromRGB(200, 200, 200)
				button.TextColor3 = Color3.fromRGB(50, 50, 50)
			end
		end
	end
	-- the anvil: Minecraft's name field + what it costs (levels; red when he has too few)
	if menu.type == "anvil" then
		if not anvilName then
			local box = Instance.new("TextBox")
			box.Name = "AnvilName"
			box.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
			box.BorderSizePixel = 0
			box.Position = UDim2.fromOffset(59, 20)
			box.Size = UDim2.fromOffset(103, 12)
			box.Font = Enum.Font.Arcade
			box.TextSize = 8
			box.TextColor3 = Color3.new(1, 1, 1)
			box.TextXAlignment = Enum.TextXAlignment.Left
			box.ClearTextOnFocus = false
			box.Text = ""
			box.ZIndex = 15
			box.Parent = container
			box.FocusLost:Connect(function()
				inventoryRemote:FireServer("rename", string.sub(box.Text, 1, 50))
			end)
			local cost = Instance.new("TextLabel")
			cost.Name = "AnvilCost"
			cost.BackgroundTransparency = 1
			cost.Position = UDim2.fromOffset(60, 67)
			cost.Size = UDim2.fromOffset(110, 9)
			cost.Font = Enum.Font.Arcade
			cost.TextSize = 8
			cost.TextXAlignment = Enum.TextXAlignment.Right
			cost.TextStrokeTransparency = 0.5
			cost.ZIndex = 15
			cost.Parent = container
			anvilName, anvilCost = box, cost
		end
		(anvilName :: TextBox).Visible = true
		local levels = tonumber(menu.cost) or 0
		local mine = tonumber(player:GetAttribute("McXpLevel")) or 0
		local label = anvilCost :: TextLabel
		label.Visible = levels > 0
		label.Text = "Enchantment Cost: " .. tostring(levels)
		label.TextColor3 = if mine >= levels or gameMode() == "creative" then Color3.fromRGB(128, 255, 32) else Color3.fromRGB(255, 96, 96)
	elseif anvilName then
		(anvilName :: TextBox).Visible = false;
		(anvilCost :: TextLabel).Visible = false
	end
	-- a villager's trades (left of its window like Minecraft): cost a, cost b -> result; a click picks it (the costs
	-- go into the slots), then take the result like any slot
	local trades = if type(menu.trades) == "table" then menu.trades else nil
	for i = 1, 7 do
		local row = tradeRows[i]
		if not row and trades then
			local button = Instance.new("TextButton")
			button.Name = "Trade" .. i
			button.Text = ""
			button.AutoButtonColor = true
			button.BorderSizePixel = 0
			button.BackgroundColor3 = Color3.fromRGB(198, 198, 198)
			button.BackgroundTransparency = 0.2
			button.Position = UDim2.fromOffset(5, 18 + (i - 1) * 20)
			button.Size = UDim2.fromOffset(88, 20)
			button.ZIndex = 13
			button.Parent = container
			local arrow = Instance.new("TextLabel")
			arrow.BackgroundTransparency = 1
			arrow.Position = UDim2.fromOffset(53, 2)
			arrow.Size = UDim2.fromOffset(12, 16)
			arrow.Font = Enum.Font.Arcade
			arrow.TextSize = 10
			arrow.Text = ">"
			arrow.TextColor3 = Color3.fromRGB(80, 80, 80)
			arrow.ZIndex = 14
			arrow.Parent = button
			local index = i - 1
			button.MouseButton1Click:Connect(function()
				inventoryRemote:FireServer("trade", index)
			end)
			row = { button = button, a = slotView(button, "CostA", 4, 2, 14), b = slotView(button, "CostB", 30, 2, 14),
				out = slotView(button, "Result", 68, 2, 14) }
			tradeRows[i] = row
		end
		if row then
			local trade = trades and trades[i]
			row.button.Visible = type(trade) == "table"
			if type(trade) == "table" then
				showStack(row.a, if type(trade[1]) == "table" then trade[1] else nil)
				showStack(row.b, if type(trade[2]) == "table" then trade[2] else nil)
				showStack(row.out, if type(trade[3]) == "table" then trade[3] else nil)
				row.button.BackgroundColor3 = if trade[4] == true then Color3.fromRGB(150, 110, 110) else Color3.fromRGB(198, 198, 198)
			end
		end
	end
	-- the enchanting table: Minecraft's three offers (levels it costs, the hint) - a click enchants (clickMenuButton)
	local offers = if type(menu.enchant) == "table" then menu.enchant else nil
	for i = 1, 3 do
		local button = enchantButtons[i]
		if not button and offers then
			local made = Instance.new("TextButton")
			made.Name = "Enchant" .. i
			made.AutoButtonColor = true
			made.BorderSizePixel = 0
			made.Position = UDim2.fromOffset(60, 14 + (i - 1) * 19)
			made.Size = UDim2.fromOffset(108, 19)
			made.Font = Enum.Font.Arcade
			made.TextSize = 7
			made.TextXAlignment = Enum.TextXAlignment.Left
			made.TextWrapped = true
			made.ZIndex = 14
			made.Parent = container
			local cost = Instance.new("TextLabel")
			cost.Name = "Cost"
			cost.BackgroundTransparency = 1
			cost.AnchorPoint = Vector2.new(1, 1)
			cost.Position = UDim2.new(1, -2, 1, -1)
			cost.Size = UDim2.fromOffset(20, 9)
			cost.Font = Enum.Font.Arcade
			cost.TextSize = 8
			cost.TextXAlignment = Enum.TextXAlignment.Right
			cost.TextColor3 = Color3.fromRGB(128, 255, 32)
			cost.TextStrokeTransparency = 0
			cost.ZIndex = 15
			cost.Parent = made
			local index = i - 1
			made.MouseButton1Click:Connect(function()
				inventoryRemote:FireServer("button", index)
			end)
			enchantButtons[i] = made
			button = made
		end
		if button then
			local offer = offers and offers[i]
			local levels = if type(offer) == "table" then tonumber(offer.cost) or 0 else 0
			button.Visible = offers ~= nil
			local mine = tonumber(player:GetAttribute("McXpLevel")) or 0
			local affordable = levels > 0 and (mine >= levels or gameMode() == "creative")
			button.Text = if levels > 0 then "  " .. tostring(offer.clue or "") .. " . . . ?" else ""
			button.BackgroundColor3 = if levels <= 0 then Color3.fromRGB(140, 130, 120)
				elseif affordable then Color3.fromRGB(205, 190, 160) else Color3.fromRGB(150, 140, 130)
			button.TextColor3 = if affordable then Color3.fromRGB(70, 60, 50) else Color3.fromRGB(90, 85, 80)
			local cost = button:FindFirstChild("Cost") :: TextLabel?
			if cost then
				cost.Text = if levels > 0 then tostring(levels) else ""
				cost.TextColor3 = if affordable then Color3.fromRGB(128, 255, 32) else Color3.fromRGB(64, 127, 16)
			end
		end
	end
	-- the furnace: the fire (burn time left) and the arrow (cooking)
	local isFurnace = menu.burn ~= nil
	furnaceFire.Visible = isFurnace
	furnaceArrow.Visible = isFurnace
	if isFurnace then
		local burn, cook = math.clamp(tonumber(menu.burn) or 0, 0, 1), math.clamp(tonumber(menu.cook) or 0, 0, 1)
		local fire = math.ceil(burn * 13) + (if burn > 0 then 1 else 0)
		furnaceFire.Position = UDim2.fromOffset(56, 36 + 14 - fire)
		furnaceFire.Size = UDim2.fromOffset(14, fire)
		furnaceFireImage.Position = UDim2.fromOffset(0, -(14 - fire))
		setPicture(furnaceFireImage, gui("furnace_lit"))
		furnaceArrow.Position = UDim2.fromOffset(79, 34)
		furnaceArrow.Size = UDim2.fromOffset(math.ceil(cook * 24), 16)
		setPicture(furnaceArrowImage, gui("furnace_burn"))
	end
end
-- endregion

local function creativeRows(): number
	local count = #creativeList()
	return math.max(0, math.ceil(count / 9) - CREATIVE_ROWS)
end

function refresh()
	local hotbarPicture, selectionPicture, windowPicture = gui("hotbar"), gui("selection"), gui("inventory")
	setPicture(hotbarBack, hotbarPicture)
	setPicture(selection, selectionPicture)
	setPicture(windowBack, windowPicture)
	-- Without Minecraft's pictures: simple grey boxes in the same places
	hotbarBack.BackgroundTransparency = if hotbarPicture then 1 else 0.3
	hotbarBack.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
	selection.BackgroundTransparency = if selectionPicture then 1 else 0.6
	windowBack.BackgroundTransparency = if windowPicture then 1 else 0
	windowBack.BackgroundColor3 = Color3.fromRGB(198, 198, 198)
	local creativePicture = gui("creative_items")
	setPicture(creativeBack, creativePicture)
	creativeBack.BackgroundTransparency = if creativePicture then 1 else 0
	creativeBack.BackgroundColor3 = Color3.fromRGB(198, 198, 198)
	selection.Position = UDim2.fromOffset(-1 + (selected - 1) * 20, -1)
	hotbar.Visible = gameMode() ~= "spectator" -- (Minecraft's spectators have no hotbar)
	for slot = 1, 9 do
		showStack(hotbarSlots[slot], hotbarStack(slot))
		showStack(creativeHotbar[slot], hotbarStack(slot))
	end
	for menuSlot = 0, 45 do
		showStack(survivalSlots[menuSlot + 1], stackAt(menuSlot))
	end
	creativeScroll = math.clamp(creativeScroll, 0, creativeRows())
	for index, view in ipairs(creativeItems) do
		local item = creativeList()[creativeScroll * 9 + index]
		showStack(view, if item then { id = item.id, n = 1 } else nil)
	end
	local rows = creativeRows()
	setPicture(scroller, if rows > 0 then gui("scroller") else gui("scroller_disabled") or gui("scroller"))
	scroller.BackgroundTransparency = if gui("scroller") then 1 else 0.2
	scroller.Position = UDim2.fromOffset(175, 18 + (if rows > 0 then math.floor(creativeScroll / rows * (112 - 15) + 0.5) else 0))
	window.Visible = inventoryView == "survival"
	creative.Visible = inventoryView == "creative"
	container.Visible = inventoryView == "container"
	if inventoryView == "container" then
		refreshContainer()
	end
	local isCreative = gameMode() == "creative"
	local scale = guiScale()
	local searching = inventoryView == "creative" and creativeTab == "search"
	searchBox.Visible = searching
	if searching then
		local searchPicture = gui("creative_search")
		if searchPicture then
			setPicture(creativeBack, searchPicture)
		end
	end
	tabTitle.Text = ""
	for _, tab in ipairs(tabs) do
		tab.frame.Visible = inventoryOpen and isCreative and inventoryView ~= "container"
		local chosen = if tab.view == "survival" then inventoryView == "survival"
			else inventoryView == "creative" and (tab.tab == creativeTab)
		if chosen and tab.name ~= "" and tab.tab ~= "search" then
			tabTitle.Text = tab.name
		end
		local picture
		if tab.row == "top" then
			picture = if chosen then (gui("tab_top_selected_1") or gui("tab_selected")) else (gui("tab_top_unselected_1") or gui("tab"))
		else
			picture = if chosen then gui("tab_bottom_selected_1") else gui("tab_bottom_unselected_1")
		end
		setPicture(tab.frame, picture)
		tab.frame.BackgroundTransparency = if picture then 1 else (if chosen then 0 else 0.4)
		tab.frame.ZIndex = if chosen then 16 else 12
		tab.icon.ZIndex = tab.frame.ZIndex + 1
		-- Minecraft: the tabs stand on the top / bottom edge of the open window, 27 pixels apart
		local width = if inventoryView == "creative" then 195 else 176
		local height = if inventoryView == "creative" then 136 else 166
		-- (search + inventory sit at the right edge like Minecraft's alignedRight tabs)
		local x = (-width / 2 + (if tab.column >= 6 then width - 27 else tab.column * 27)) * scale
		if tab.row == "top" then
			tab.frame.AnchorPoint = Vector2.new(0, 1)
			tab.frame.Position = UDim2.new(0.5, x, 0.5, (-height / 2 + 4) * scale)
		else
			tab.frame.AnchorPoint = Vector2.new(0, 0)
			tab.frame.Position = UDim2.new(0.5, x, 0.5, (height / 2 - 4) * scale)
		end
		setPicture(tab.icon, iconContent(tab.iconItem))
	end
	local carried = if inventoryView == "creative" and creativeCursor then creativeCursor
		elseif type(state.carried) == "table" then state.carried else nil
	showStack(cursor, carried)
	cursorFrame.Visible = inventoryOpen and carried ~= nil
end

local function showItemName()
	local stack = hotbarStack(selected)
	itemName.Text = if stack then tostring(stack.name or stack.id) else ""
	nameShownAt = os.clock()
end

local function select(slot: number)
	selected = slot
	refresh()
	showItemName()
end
-- endregion

-- region inventory open / close + clicks
local setInventory, scrollCreative
do -- (its own block: these locals do not count towards the 200 of the script)
	local function blockMovement()
		return Enum.ContextActionResult.Sink
	end

	local function updatePreview()
		preview:ClearAllChildren()
		local character = player.Character
		if not character then
			return
		end
		pcall(function()
			local archivable = character.Archivable
			character.Archivable = true
			local copy = character:Clone()
			character.Archivable = archivable
			for _, item in ipairs(copy:GetDescendants()) do
				if item:IsA("BaseScript") then
					item:Destroy()
				elseif item:IsA("BasePart") or item:IsA("Decal") then
					item.LocalTransparencyModifier = 0
				end
			end
			copy:PivotTo(CFrame.new(0, 0, 0) * CFrame.Angles(0, math.rad(200), 0))
			local world = Instance.new("WorldModel")
			world.Parent = preview
			copy.Parent = world
			local camera = Instance.new("Camera")
			camera.FieldOfView = 30
			camera.CFrame = CFrame.lookAt(Vector3.new(0, 0.3, 12), Vector3.new(0, 0.3, 0))
			camera.Parent = preview
			preview.CurrentCamera = camera
		end)
	end

	local function shiftDown(): boolean
		return UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) or UserInputService:IsKeyDown(Enum.KeyCode.RightShift)
	end

	-- survival / adventure (and the inventory tab in creative): Minecraft's own click, done in Minecraft
	function clickSurvival(menuSlot: number, button: number)
		if gameMode() == "spectator" then
			return
		end
		inventoryRemote:FireServer("click", menuSlot, button, shiftDown())
	end

	-- creative: the item on the mouse stays here until it is put into a slot (Minecraft does the same)
	local function putCreative(menuSlot: number, stack: any)
		inventoryRemote:FireServer("creative", menuSlot, if stack then stack.id else nil, if stack then stack.n else 0)
		-- shown at once (Minecraft's answer comes a moment later and says the same)
		state.slots[menuSlot + 1] = if stack then { id = stack.id, n = stack.n, name = stack.name, max = stack.max } else false
	end

	function clickCreativeItem(index: number, button: number)
		local item = creativeList()[creativeScroll * 9 + index + 1]
		if creativeCursor then
			if item and creativeCursor.id == item.id and button == 0 then
				creativeCursor.n = math.min(creativeCursor.n + 1, creativeCursor.max or 64) -- one more of the same
			else
				creativeCursor = nil -- an item put back on the item list is gone (Minecraft)
			end
		elseif item then
			local max = tonumber(item.max) or 64
			if shiftDown() then
				-- shift: a whole stack into the first free hotbar / inventory slot
				for _, menuSlot in ipairs({ 36, 37, 38, 39, 40, 41, 42, 43, 44 }) do
					if not stackAt(menuSlot) then
						putCreative(menuSlot, { id = item.id, n = max, name = item.name, max = max })
						refresh()
						return
					end
				end
				for menuSlot = 9, 35 do
					if not stackAt(menuSlot) then
						putCreative(menuSlot, { id = item.id, n = max, name = item.name, max = max })
						break
					end
				end
			else
				creativeCursor = { id = item.id, n = if button == 1 then max else 1, name = item.name, max = max }
			end
		end
		refresh()
	end

	function clickCreativeHotbar(slot: number, button: number)
		local menuSlot = 35 + slot
		local stack = stackAt(menuSlot)
		if shiftDown() and not creativeCursor then
			putCreative(menuSlot, nil) -- shift-click: empty it
		elseif creativeCursor then
			if stack and stack.id == creativeCursor.id then
				local max = tonumber(stack.max) or 64
				local add = if button == 1 then 1 else creativeCursor.n
				local total = math.min(max, stack.n + add)
				local used = total - stack.n
				putCreative(menuSlot, { id = stack.id, n = total, name = stack.name, max = stack.max })
				creativeCursor.n -= used
				if creativeCursor.n <= 0 then
					creativeCursor = nil
				end
			elseif button == 1 and not stack then
				putCreative(menuSlot, { id = creativeCursor.id, n = 1, name = creativeCursor.name, max = creativeCursor.max })
				creativeCursor.n -= 1
				if creativeCursor.n <= 0 then
					creativeCursor = nil
				end
			else
				local old = stack
				putCreative(menuSlot, creativeCursor)
				creativeCursor = if old then { id = old.id, n = old.n, name = old.name, max = old.max } else nil
			end
		elseif stack then
			if button == 1 then
				-- right click: half of it on the mouse
				local half = math.ceil(stack.n / 2)
				creativeCursor = { id = stack.id, n = half, name = stack.name, max = stack.max }
				putCreative(menuSlot, if stack.n - half > 0 then { id = stack.id, n = stack.n - half, name = stack.name,
					max = stack.max } else nil)
			else
				creativeCursor = { id = stack.id, n = stack.n, name = stack.name, max = stack.max }
				putCreative(menuSlot, nil)
			end
		end
		refresh()
	end

	-- a click on the dark part around the window: throw what is on the mouse away (Minecraft)
	local function clickOutside(button: number)
		if not inventoryOpen then
			return
		end
		if inventoryView == "creative" and creativeCursor then
			local stack = creativeCursor
			creativeCursor = nil
			local count = if button == 1 then 1 else stack.n
			inventoryRemote:FireServer("creative", -1, stack.id, count)
			if button == 1 and stack.n > 1 then
				creativeCursor = { id = stack.id, n = stack.n - 1, name = stack.name, max = stack.max }
			end
			refresh()
		elseif inventoryView == "survival" and type(state.carried) == "table" then
			clickSurvival(-999, button)
		elseif inventoryView == "container" and type(state.carried) == "table" then
			inventoryRemote:FireServer("click", -999, button, false, true)
		end
	end
	dim.MouseButton1Click:Connect(function()
		clickOutside(0)
	end)
	dim.MouseButton2Click:Connect(function()
		clickOutside(1)
	end)

	function setView(view: string)
		if view == inventoryView then
			return
		end
		if inventoryView == "creative" and creativeCursor then
			creativeCursor = nil -- (Minecraft keeps it; here it goes away like an item put back)
		end
		if inventoryView == "survival" then
			inventoryRemote:FireServer("close") -- the crafting grid + the mouse go back into the inventory
		end
		inventoryView = view
		if view == "survival" then
			updatePreview()
		end
		refresh()
	end

	function setInventory(open: boolean)
		if inventoryOpen == open then
			return
		end
		if open and gameMode() == "spectator" then
			return -- (Minecraft's spectators have no inventory)
		end
		inventoryOpen = open
		dim.Visible = open
		player:SetAttribute("McGuiOpen", open) -- MinecraftPlayer frees the mouse and stops walking
		if open then
			inventoryView = if gameMode() == "creative" then "creative" else "survival"
			updatePreview()
			ContextActionService:BindActionAtPriority("MinecraftInventory", blockMovement, false,
				Enum.ContextActionPriority.High.Value, Enum.KeyCode.W, Enum.KeyCode.A, Enum.KeyCode.S, Enum.KeyCode.D,
				Enum.KeyCode.Space, Enum.KeyCode.Up, Enum.KeyCode.Down, Enum.KeyCode.Left, Enum.KeyCode.Right)
		else
			ContextActionService:UnbindAction("MinecraftInventory")
			if creativeCursor then
				-- the item on the mouse goes into the first free slot (else it is gone)
				for menuSlot = 36, 44 do
					if not stackAt(menuSlot) then
						putCreative(menuSlot, creativeCursor)
						break
					end
				end
				creativeCursor = nil
			end
			inventoryRemote:FireServer("close") -- crafting grid + mouse back into the inventory (Minecraft)
			hovered = nil
			highlight.Visible = false
			hoverName.Visible = false
		end
		refresh()
	end

	-- the wheel scrolls the creative item list
	function scrollCreative(step: number)
		creativeScroll = math.clamp(creativeScroll + step, 0, creativeRows())
		refresh()
	end

	-- a new state from Minecraft (after every click, placed block, /gamemode, picked up item ...)
	local lastServerSel = -1
	inventoryRemote.OnClientEvent:Connect(function(kind, newState)
		if kind ~= "state" or type(newState) ~= "table" or type(newState.slots) ~= "table" then
			return
		end
		local first = not stateArrived
		stateArrived = true
		local oldMode = state.gm
		state = newState
		if type(newState.sel) == "number" and (first or newState.sel + 1 ~= selected) and newState.sel ~= lastServerSel then
			selected = math.clamp(newState.sel + 1, 1, 9) -- Minecraft chose another slot (middle click picked a block)
		end
		lastServerSel = if type(newState.sel) == "number" then newState.sel else lastServerSel
		if inventoryOpen and (newState.gm == "spectator" or (oldMode ~= newState.gm)) then
			setInventory(false) -- the game mode changed: the window that fits comes with the next E
		end
		-- a chest / furnace opened (his right click) - or closed by Minecraft (broken, too far)
		if type(newState.menu) == "table" and inventoryView ~= "container" then
			if not inventoryOpen then
				setInventory(true)
			end
			inventoryView = "container"
		elseif type(newState.menu) ~= "table" and inventoryView == "container" then
			inventoryView = if gameMode() == "creative" then "creative" else "survival"
			if inventoryOpen then
				setInventory(false)
			end
		end
		refresh()
		if first then
			showItemName()
		end
	end)
end
-- endregion

-- region building: aim, use, break (with Minecraft's breaking time in survival)
local target, direction
do -- (its own block: these locals do not count towards the 200 of the script)
	local selectionBoxes: { SelectionBox } = {}
	local selectionHolder = Instance.new("Folder")
	selectionHolder.Name = "MinecraftBlockSelection"
	selectionHolder.Parent = workspace
	local selectionPart = Instance.new("Part") -- the outline of a whole cube
	selectionPart.Name = "Cube"
	selectionPart.Anchored = true
	selectionPart.CanCollide = false
	selectionPart.CanQuery = false
	selectionPart.CanTouch = false
	selectionPart.Transparency = 1
	selectionPart.Parent = selectionHolder

	local function selectionBox(index: number): SelectionBox
		local box = selectionBoxes[index]
		if not box then
			box = Instance.new("SelectionBox")
			box.Color3 = Color3.new(0, 0, 0)
			box.LineThickness = 0.03
			box.SurfaceTransparency = 1
			box.Transparency = 0.35
			box.Parent = selectionHolder
			selectionBoxes[index] = box
		end
		return box
	end

	-- the cracks while breaking (survival): a box around the block with Minecraft's destroy_stage pictures. Every stage
	-- is a NEW part with new Textures (pictures set before it goes into the world): Roblox did not draw a picture again
	-- on a Texture that had one before and was taken out of the world (the cracks showed only on the first block).
	local crackPart: Part? = nil
	local shownStage = -1

	local function showCracks(target, stage: number)
		if stage < 0 or not target then
			if crackPart then
				crackPart:Destroy()
				crackPart = nil
			end
			shownStage = -1
			return
		end
		local box = target.box
		if stage ~= shownStage or not crackPart or not crackPart.Parent then
			shownStage = stage
			local key = assets and assets.gui and assets.gui["destroy_" .. stage]
			local content = if key then worldContent(key) else nil
			local part = Instance.new("Part")
			part.Name = "Cracks"
			part.Anchored = true
			part.CanCollide = false
			part.CanQuery = false
			part.CanTouch = false
			part.Transparency = 1
			part.CastShadow = false
			part.Size = box.Size + Vector3.one * 0.04
			part.CFrame = box.CFrame
			if content then
				for _, normal in ipairs(Enum.NormalId:GetEnumItems()) do
					local texture = Instance.new("Texture")
					texture.Face = normal
					texture.StudsPerTileU = assets.scale
					texture.StudsPerTileV = assets.scale
					texture.TextureContent = content
					pcall(function()
						texture.ResampleMode = Enum.ResamplerMode.Pixelated
					end)
					texture.Parent = part
				end
			end
			part.Parent = workspace
			if crackPart then
				crackPart:Destroy()
			end
			crackPart = part
		end
		local part = crackPart :: Part
		part.Size = box.Size + Vector3.one * 0.04
		part.CFrame = box.CFrame
	end

	local rayParams = RaycastParams.new()
	rayParams.FilterType = Enum.RaycastFilterType.Include

	target = nil -- the block under the crosshair: {x, y, z, normal, face, hit, name, part, box, parts}
	local targetNpc = nil -- or the NPC of a Minecraft player under the crosshair (left click hits him)
	local targetMob = nil -- or the id of a Minecraft mob under the crosshair (left click hits it: Minecraft's attack)

	local function blockOf(position: Vector3): (number, number, number)
		local scale = assets.scale
		return math.floor(position.X / scale), math.floor(position.Y / scale) + assets.minY, math.floor(position.Z / scale)
	end

	local function blockCenter(x: number, y: number, z: number): Vector3
		local scale = assets.scale
		return Vector3.new((x + 0.5) * scale, (y - assets.minY + 0.5) * scale, (z + 0.5) * scale)
	end

	local DIRECTIONS = { -- normal -> Minecraft direction
		{ Vector3.new(0, 0, -1), "north" }, { Vector3.new(0, 0, 1), "south" }, { Vector3.new(1, 0, 0), "east" },
		{ Vector3.new(-1, 0, 0), "west" }, { Vector3.new(0, 1, 0), "up" }, { Vector3.new(0, -1, 0), "down" },
	}
	function direction(normal: Vector3): string
		local best, bestDot = "up", -math.huge
		for _, entry in ipairs(DIRECTIONS) do
			local dot = entry[1]:Dot(normal)
			if dot > bestDot then
				best, bestDot = entry[2], dot
			end
		end
		return best
	end

	local function eyeAndLook(): (Vector3?, Vector3?)
		local eye, look = player:GetAttribute("McEye"), player:GetAttribute("McLook")
		if typeof(eye) == "Vector3" and typeof(look) == "Vector3" then
			return eye, look.Unit
		end
		local camera = workspace.CurrentCamera
		if not camera then
			return nil, nil
		end
		local ray = camera:ViewportPointToRay(camera.ViewportSize.X / 2, camera.ViewportSize.Y / 2)
		return ray.Origin, ray.Direction
	end

	local function findTarget()
		target = nil
		targetNpc = nil
		targetMob = nil
		local worldFolder = workspace:FindFirstChild("MinecraftWorld")
		local character = player.Character
		if not assets or not worldFolder or not character or inventoryOpen or gameMode() == "spectator" then
			return
		end
		-- Like Minecraft: from the eyes where the player looks (also in third person / front view)
		local origin, look = eyeAndLook()
		if not origin or not look then
			return
		end
		local npcFolder = workspace:FindFirstChild("BridgeRemotePlayers")
		local mobsHere = workspace:FindFirstChild("MinecraftMobs")
		local aimAt = { worldFolder }
		if npcFolder then
			table.insert(aimAt, npcFolder)
		end
		if mobsHere then
			table.insert(aimAt, mobsHere)
		end
		local thingsHere = workspace:FindFirstChild("MinecraftThings") -- (the dragon, end crystals can be hit)
		if thingsHere then
			table.insert(aimAt, thingsHere)
		end
		rayParams.FilterDescendantsInstances = aimAt
		local result = workspace:Raycast(origin, look * (reach() + 1) * assets.scale, rayParams)
		-- what you only bump into (the upper half of a fence) is not aimed at: look past it (Minecraft aims at the outline)
		for _ = 1, 4 do
			if not result or not result.Instance:GetAttribute("McSolidOnly") then
				break
			end
			local from = result.Position + look * 0.01
			local left = (reach() + 1) * assets.scale - (from - origin).Magnitude
			result = if left > 0 then workspace:Raycast(from, look * left, rayParams) else nil
		end
		if not result then
			return
		end
		local distance = (result.Position - origin).Magnitude
		local mobId = result.Instance:GetAttribute("McMob")
		if type(mobId) == "number" then
			if distance <= (attackReach() + 0.5) * assets.scale then
				targetMob = mobId
			end
			return
		end
		if npcFolder and result.Instance:IsDescendantOf(npcFolder) then
			local model = result.Instance:FindFirstAncestorOfClass("Model")
			while model and model:GetAttribute("McUserId") == nil do
				model = model:FindFirstAncestorOfClass("Model")
			end
			if model and distance <= (attackReach() + 0.5) * assets.scale and model:GetAttribute("McGameMode") ~= "spectator" then
				targetNpc = model
			end
			return
		end
		if distance > reach() * assets.scale then
			return
		end
		local x, y, z = blockOf(result.Position - result.Normal * 0.02)
		local part = result.Instance :: BasePart
		-- a model block (lever, stairs, ...): its parts are in a Model named like the block; cubes: the part has the name
		local holder = part.Parent
		local isModel = holder ~= nil and holder:IsA("Model")
		local cell = if isModel then (holder :: Instance):GetAttribute("McBlock") else nil
		if typeof(cell) == "Vector3" then
			x, y, z = cell.X, cell.Y, cell.Z -- (a piston arm reaches into the next block: it still belongs to its own)
		end
		local name = if isModel then (holder :: Instance).Name else part.Name
		local parts = {}
		if isModel then
			for _, item in ipairs((holder :: Instance):GetChildren()) do
				if item:IsA("BasePart") and item.CanQuery and not item:GetAttribute("McSolidOnly") then
					table.insert(parts, item)
				end
			end
		end
		-- the cube of the block (for whole blocks inside merged parts) / the model's parts together
		local box = selectionPart
		if #parts > 0 then
			local minV, maxV = Vector3.one * math.huge, -Vector3.one * math.huge
			for _, item in ipairs(parts) do
				local half = item.Size / 2
				minV = minV:Min(item.Position - half)
				maxV = maxV:Max(item.Position + half)
			end
			box = { Size = maxV - minV, CFrame = CFrame.new((minV + maxV) / 2) } :: any
		else
			box = { Size = Vector3.one * assets.scale, CFrame = CFrame.new(blockCenter(x, y, z)) } :: any
		end
		target = { x = x, y = y, z = z, normal = result.Normal, face = direction(result.Normal), hit = result.Position,
			name = name, part = part, parts = parts, box = box }
	end

	local function showOutline()
		local used = 0
		if target then
			if #target.parts > 0 then
				-- Minecraft outlines the shape of the block (its boxes)
				for _, item in ipairs(target.parts) do
					used += 1
					local box = selectionBox(used)
					box.Adornee = item
					box.Visible = true
				end
			else
				selectionPart.Size = Vector3.one * (assets.scale + 0.04)
				selectionPart.CFrame = CFrame.new(blockCenter(target.x, target.y, target.z))
				used += 1
				local box = selectionBox(used)
				box.Adornee = selectionPart
				box.Visible = true
			end
		end
		for index = used + 1, #selectionBoxes do
			selectionBoxes[index].Visible = false
			selectionBoxes[index].Adornee = nil
		end
	end

	-- My own arm swings when I hit / build: the script MinecraftPlayer plays Minecraft's swing (replicates to the others);
	-- the server tells Minecraft ("sw": the mannequin swings too)
	local function swingArm()
		player:SetAttribute("McSwingAt", os.clock())
	end

	local function onGround(): boolean
		return player:GetAttribute("McGround") ~= false -- (MinecraftPlayer: the feet on a block)
	end

	local function myRoot(): Vector3?
		local character = player.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		return if root and root:IsA("BasePart") then root.Position else nil
	end

	-- every click has a number: the server says "answer" with it when Minecraft has answered (the block built here)
	local clickCount = 0
	local function editInfo(): { [string]: any }
		local _, look = eyeAndLook()
		clickCount = clickCount % 1000000 + 1
		return { face = target and target.face, hit = target and target.hit, slot = selected - 1, look = look,
			ground = onGround(), root = myRoot(), id = clickCount }
	end

	-- region building at once
	--[[
		Like Minecraft's own client: a plain block (planks, stone, dirt) put on a plain block (one a click does nothing on:
		not a crafting table, a door) is there at once - here, before the server and Minecraft have answered. Jumping up a
		pillar you land on it (the server's copy of you is a moment behind; it came too late and pushed you off). Not
		where somebody stands (Minecraft's hitbox; mine: where I am right now - the server gets the same position, so it
		and Minecraft decide the same). The server's block takes its place; if Minecraft said no, it is gone again.
	]]
	local GHOST_AFTER_ANSWER = 0.5 -- s: Minecraft has answered, the server's block is still not there: it said no
	local GHOST_LONGEST = 3 -- s
	local TOUCH = 0.01 -- studs: standing on the block is not standing in it (Minecraft)
	local FACE_STEPS = { up = Vector3.new(0, 1, 0), down = Vector3.new(0, -1, 0), north = Vector3.new(0, 0, -1),
		south = Vector3.new(0, 0, 1), east = Vector3.new(1, 0, 0), west = Vector3.new(-1, 0, 0) }
	local CUBE_FACES = { up = Enum.NormalId.Top, down = Enum.NormalId.Bottom, north = Enum.NormalId.Front,
		south = Enum.NormalId.Back, east = Enum.NormalId.Right, west = Enum.NormalId.Left }
	local ghosts = {} -- "x,y,z" -> {part, id, center, madeAt, answeredAt}
	local overlapParams = OverlapParams.new()
	overlapParams.FilterType = Enum.RaycastFilterType.Include

	local function plainCube(look: any): boolean
		return look ~= nil and look.cube == true and not look.single and not look.fluid and type(look.faces) == "table"
	end

	-- a click on this block builds (does nothing else): like the server's clickBuilds
	local function clickBuilds(name: string, look: any, sneaking: boolean): boolean
		if not plainCube(look) then
			return false
		end
		if look.use ~= nil then
			return look.use ~= true or sneaking
		end
		return not string.find(name, "[", 1, true) and (sneaking or not string.find(name, "_table$"))
			and name ~= "minecraft:jukebox"
	end

	local function bodyInBlock(center: Vector3, scale: number, mine: Vector3?): boolean
		local Character = require(ReplicatedStorage:WaitForChild("MinecraftCharacter") :: any)
		for _, other in ipairs(Players:GetPlayers()) do
			local character = other.Character
			local root = character and character:FindFirstChild("HumanoidRootPart")
			if root and root:IsA("BasePart") and character:GetAttribute("McGameMode") ~= "spectator" then
				local p = if other == player and mine then mine else root.Position
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

	local function cellTaken(worldFolder: Instance, center: Vector3, scale: number): boolean
		overlapParams.FilterDescendantsInstances = { worldFolder }
		return #workspace:GetPartBoundsInBox(CFrame.new(center), Vector3.one * (scale - 0.1), overlapParams) > 0
	end

	local function buildAtOnce(id: number)
		local mode = gameMode()
		local worldFolder = workspace:FindFirstChild("MinecraftWorld")
		local character = player.Character
		if not target or not assets or not worldFolder or (mode ~= "creative" and mode ~= "survival") then
			return
		end
		local stack = hotbarStack(selected)
		local item = stack and itemInfo(stack.id)
		local block = item and item.block
		if type(block) ~= "string" or string.find(block, "[", 1, true) then
			return
		end
		local look = assets.blocks and assets.blocks[block]
		local sneaking = character ~= nil and character:GetAttribute("McSneak") == true
		if not plainCube(look) or not clickBuilds(target.name, assets.blocks[target.name], sneaking) or #target.parts > 0 then
			return
		end
		local step = FACE_STEPS[target.face]
		if not step then
			return
		end
		local x, y, z = target.x + step.X, target.y + step.Y, target.z + step.Z
		local lowest, highest = assets.minY, assets.maxY
		if type(assets.dims) == "table" and #assets.dims > 1 then
			-- (every dimension at its own height: the one this block is in)
			local d = math.clamp((y + 128) // 1024, 0, #assets.dims - 1)
			local dim = assets.dims[d + 1]
			if type(dim) == "table" then
				lowest = (tonumber(dim.minY) or 0) + (tonumber(dim.shift) or 0)
				highest = (tonumber(dim.maxY) or 256) + (tonumber(dim.shift) or 0)
			end
		end
		if y < lowest or y >= highest then
			return
		end
		local scale = assets.scale
		local center = blockCenter(x, y, z)
		local key = x .. "," .. y .. "," .. z
		if ghosts[key] or cellTaken(worldFolder, center, scale) or bodyInBlock(center, scale, myRoot()) then
			return
		end
		local folder = worldFolder:FindFirstChild("McAtOnce")
		if not folder then
			folder = Instance.new("Folder")
			folder.Name = "McAtOnce"
			folder.Parent = worldFolder
		end
		local part = Instance.new("Part")
		part.Name = block -- (aimed at like the server's blocks: the next one goes on top of it)
		part.Anchored = true
		part.CanCollide = true
		part.Size = Vector3.one * scale
		part.CFrame = CFrame.new(center)
		part.Material = Enum.Material.SmoothPlastic
		part.TopSurface = Enum.SurfaceType.Smooth
		part.BottomSurface = Enum.SurfaceType.Smooth
		part.Color = if type(look.color) == "table" then Color3.fromRGB(look.color[1], look.color[2], look.color[3]) else part.Color
		if look.transparent then
			part.Transparency = 1
			part.CastShadow = false
		end
		for faceName, normalId in pairs(CUBE_FACES) do
			local picture = look.faces[faceName]
			if picture then
				local texture = Instance.new("Texture")
				texture.Name = "McTexture"
				texture.Face = normalId
				texture.StudsPerTileU = scale
				texture.StudsPerTileV = scale
				texture:SetAttribute("McTexture", picture) -- (the picture: applyTexture, like the server's blocks)
				texture.Parent = part
			end
		end
		part.Parent = folder
		ghosts[key] = { part = part, id = id, center = center, madeAt = os.clock(), answeredAt = nil }
	end

	editRemote.OnClientEvent:Connect(function(kind, id)
		if kind == "answer" then
			for _, ghost in pairs(ghosts) do
				if ghost.id == id and not ghost.answeredAt then
					ghost.answeredAt = os.clock()
				end
			end
		end
	end)

	-- the server's block is there (it takes the place) - or Minecraft said no / nothing came: gone
	RunService.Heartbeat:Connect(function()
		if next(ghosts) == nil then
			return
		end
		local worldFolder = workspace:FindFirstChild("MinecraftWorld")
		local now = os.clock()
		for key, ghost in pairs(ghosts) do
			local gone = not worldFolder or not ghost.part.Parent or now - ghost.madeAt > GHOST_LONGEST
				or (ghost.answeredAt ~= nil and now - ghost.answeredAt > GHOST_AFTER_ANSWER)
			if not gone and worldFolder then
				overlapParams.FilterDescendantsInstances = { worldFolder }
				for _, part in ipairs(workspace:GetPartBoundsInBox(CFrame.new(ghost.center), Vector3.one * 0.2, overlapParams)) do
					if part ~= ghost.part and part.Parent and part.Parent.Name ~= "McAtOnce" then
						gone = true -- (the server's block)
						break
					end
				end
			end
			if gone then
				ghosts[key] = nil
				ghost.part:Destroy()
			end
		end
	end)
	-- endregion

	-- region breaking (survival: Minecraft's breaking time - the server asks Minecraft how fast for his item, this block)
	local mining = nil -- {x, y, z, name, progress, perTick, swungAt}
	local breakDelay = 0 -- Minecraft waits 5 ticks after a block broke before the next one starts
	local speeds = {} -- "block|item|ground" -> progress per tick (from Minecraft)

	-- Minecraft's formula for the hand (until Minecraft's own answer is there): 1 / hardness / (30, or 100 when the
	-- block needs a tool), 5 x slower in the air
	local function guessSpeed(name: string): number
		local look = assets and assets.blocks and assets.blocks[name]
		local hardness = if look then tonumber(look.hard) else nil
		if not hardness then
			return 1 / 1.5 / 100
		end
		if hardness < 0 then
			return 0
		end
		if hardness == 0 then
			return 1
		end
		return 1 / hardness / (if look.tool then 100 else 30) * (if onGround() then 1 else 0.2)
	end

	local function startMining()
		if not target then
			return
		end
		local stack = hotbarStack(selected)
		local key = target.name .. "|" .. (if stack then stack.id else "") .. "|" .. tostring(onGround())
		mining = { x = target.x, y = target.y, z = target.z, name = target.name, progress = 0, toldAt = -math.huge,
			perTick = speeds[key] or guessSpeed(target.name), swungAt = -math.huge }
		if speeds[key] == nil then
			local wanted = mining
			task.spawn(function()
				local ok, progress = pcall(function()
					return miningSpeed:InvokeServer(wanted.x, wanted.y, wanted.z, selected - 1, onGround())
				end)
				if ok and type(progress) == "number" then
					speeds[key] = progress
					if mining == wanted then
						wanted.perTick = progress
					end
				end
			end)
		end
	end

	local function stopMining()
		mining = nil
		showCracks(nil, -1)
	end
	-- endregion

	-- eating / drinking (right button held with food / a potion): Minecraft's time (1.6 s for most food), then "eat"
	eating = nil
	function startEating(): boolean
		local stack = hotbarStack(selected)
		local info = stack and itemInfo(stack.id)
		local mode = gameMode()
		if not info or (info.use ~= "eat" and info.use ~= "drink") or mode == "spectator" then
			return false
		end
		-- a block that does something on a right click (chest, door, crafting table) goes first (Minecraft)
		if target and assets and assets.blocks then
			local look = assets.blocks[target.name or ""]
			if look and look.use then
				return false
			end
		end
		local food = tonumber(player:GetAttribute("McFood")) or 20
		if info.use == "eat" and info.always ~= true and food >= 20 and mode ~= "creative" then
			return false -- (Minecraft: full - no eating, the item is used normally)
		end
		eating = { id = stack.id, use = info.use, started = os.clock(), duration = tonumber(info.useTime) or 1.6, crumbsAt = 0 }
		player:SetAttribute("McEating", info.use)
		return true
	end
	function stopEating()
		eating = nil
		player:SetAttribute("McEating", nil)
	end

	-- bows, crossbows, tridents: right button held = charging (the view narrows a little like Minecraft's bow), let go =
	-- Minecraft shoots / throws with the power of the time held
	local charging: any = nil -- {id, slot, started, full}
	local chargeFov: number? = nil
	local function startCharging(): boolean
		local stack = hotbarStack(selected)
		local info = stack and itemInfo(stack.id)
		if not info or (info.use ~= "charge" and info.use ~= "block") or gameMode() == "spectator" then
			return false
		end
		if target and assets and assets.blocks then
			local look = assets.blocks[target.name or ""]
			if look and look.use then
				return false -- (a chest / door in front goes first)
			end
		end
		charging = { id = stack.id, slot = selected, started = os.clock(), full = tonumber(info.useTime) or 1,
			block = info.use == "block" }
		player:SetAttribute("McEating", "charge")
		if info.use == "block" then
			player:SetAttribute("McBlocking", true) -- (a shield: up while held - Minecraft blocks hits from in front)
		end
		return true
	end
	local function stopCharging(shoot: boolean)
		local was = charging
		charging = nil
		player:SetAttribute("McEating", nil)
		player:SetAttribute("McBlocking", nil)
		if was and was.block then
			shoot = false -- (a shield shoots nothing)
		end
		local camera = workspace.CurrentCamera
		if chargeFov and camera then
			camera.FieldOfView = chargeFov
		end
		chargeFov = nil
		if shoot and was then
			local _, look = eyeAndLook()
			inventoryRemote:FireServer("release", was.slot - 1, os.clock() - was.started, look)
		end
	end

	local function act(action: string, repeated: boolean?)
		local mode = gameMode()
		if mode == "spectator" then
			return
		end
		if action == "break" then
			if targetMob then
				-- a mob: Minecraft's own attack with his item (crit when falling, sword sweep, knockback)
				swingArm()
				local character = player.Character
				local rootPart = character and character:FindFirstChild("HumanoidRootPart")
				local velocityY = if rootPart and rootPart:IsA("BasePart") then rootPart.AssemblyLinearVelocity.Y else 0
				local falling = not onGround() and velocityY < 0 and player:GetAttribute("McFluid") == nil
					and player:GetAttribute("McFlying") ~= true
				attackRemote:FireServer(nil, { falling = falling, sprint = character ~= nil
					and character:GetAttribute("McSprint") == true }, targetMob)
				return
			end
			if targetNpc then
				swingArm()
				-- hit the Minecraft player (Minecraft does the damage: with the item in the hand, its charge, and a
				-- critical hit when falling - not on the ground, not in water, not flying, not sprinting)
				local character = player.Character
				local rootPart = character and character:FindFirstChild("HumanoidRootPart")
				local velocityY = if rootPart and rootPart:IsA("BasePart") then rootPart.AssemblyLinearVelocity.Y else 0
				local falling = not onGround() and velocityY < 0 and player:GetAttribute("McFluid") == nil
					and player:GetAttribute("McFlying") ~= true
				attackRemote:FireServer(targetNpc, { falling = falling, sprint = character ~= nil
					and character:GetAttribute("McSprint") == true })
				return
			end
			if not target then
				if not repeated then
					-- a hit into the air: Minecraft swings the arm anyway (not again while the button is only held)
					swingArm()
					swingRemote:FireServer()
				end
				return
			end
			if mode == "creative" then
				swingArm()
				editRemote:FireServer("break", target.x, target.y, target.z, editInfo())
			elseif mode == "survival" and not repeated then
				startMining()
			elseif mode == "adventure" and not repeated then
				swingArm() -- (adventure: blocks do not break)
				swingRemote:FireServer()
			end
			return
		end
		if not target then
			-- into the air: only the item is used (a bucket takes / pours water where you look, a snowball flies)
			local eye, look = eyeAndLook()
			if hotbarStack(selected) and eye and look and assets then
				swingArm()
				local x, y, z = blockOf(eye)
				editRemote:FireServer("use", x, y, z, { air = true, slot = selected - 1, look = look, ground = onGround(),
					root = myRoot() })
			end
			return
		end
		-- right click: Minecraft decides (open / press / pull - or place the item in the hand on that face)
		swingArm()
		local info = editInfo()
		buildAtOnce(info.id)
		editRemote:FireServer("use", target.x, target.y, target.z, info)
	end

	local held = {} -- "break" / "use" -> time of the last action while the button is held

	local function pickBlock()
		findTarget()
		if target and gameMode() ~= "spectator" then
			inventoryRemote:FireServer("pick", target.x, target.y, target.z)
		end
	end

	UserInputService.InputBegan:Connect(function(input, processed)
		if input.KeyCode == Enum.KeyCode.E and not processed and player:GetAttribute("McMenuOpen") ~= true then
			setInventory(not inventoryOpen)
			return
		end
		if input.KeyCode == Enum.KeyCode.Escape and inventoryOpen then
			setInventory(false)
			return
		end
		if player:GetAttribute("McMenuOpen") == true then
			return -- (the settings menu is open)
		end
		if processed or inventoryOpen then
			return
		end
		local slot = HOTBAR_KEYS[input.KeyCode]
		if slot then
			select(slot)
		elseif input.KeyCode == Enum.KeyCode.Q and gameMode() ~= "spectator" then
			-- Q: throw one away, Ctrl + Q: the whole stack (Minecraft)
			local _, look = eyeAndLook()
			local all = UserInputService:IsKeyDown(Enum.KeyCode.LeftControl)
			swingArm()
			inventoryRemote:FireServer("drop", all, selected - 1, look)
		elseif input.UserInputType == Enum.UserInputType.MouseButton1 then
			findTarget()
			act("break")
			held["break"] = os.clock()
		elseif input.UserInputType == Enum.UserInputType.MouseButton2 then
			-- the mouse is always caught like in Minecraft (MinecraftPlayer): the right button only builds
			findTarget()
			held.use = os.clock()
			if startEating() then
				return -- (food / a potion in the hand: held = eat / drink, like Minecraft)
			end
			act("use")
		elseif input.UserInputType == Enum.UserInputType.MouseButton3 then
			pickBlock()
		end
	end)
	UserInputService.InputEnded:Connect(function(input)
		if input.UserInputType == Enum.UserInputType.MouseButton1 then
			held["break"] = nil
			stopMining()
		elseif input.UserInputType == Enum.UserInputType.MouseButton2 then
			held.use = nil
			stopEating()
		end
	end)
	-- the mouse wheel goes through the hotbar (like Minecraft) - in the creative inventory it scrolls the items
	UserInputService.InputChanged:Connect(function(input, processed)
		if input.UserInputType ~= Enum.UserInputType.MouseWheel then
			return
		end
		local step = if input.Position.Z > 0 then -1 elseif input.Position.Z < 0 then 1 else 0
		if inventoryOpen then
			if inventoryView == "creative" and step ~= 0 then
				scrollCreative(step)
			end
			return
		end
		if processed then
			return
		end
		if step ~= 0 then
			select((selected - 1 + step) % 9 + 1)
		end
	end)

	RunService.RenderStepped:Connect(function(dt)
		findTarget()
		showOutline()
		local now = os.clock()
		local mode = gameMode()
		-- holding the left button: creative breaks one block every 5 ticks, survival counts the breaking time
		if held["break"] and mode == "survival" then
			breakDelay = math.max(0, breakDelay - dt)
			if not target or targetNpc then
				stopMining()
			elseif breakDelay <= 0 then
				if not mining or mining.x ~= target.x or mining.y ~= target.y or mining.z ~= target.z or mining.name ~= target.name then
					startMining()
				end
				if mining then
					mining.progress += mining.perTick * 20 * dt
					if now - mining.swungAt >= 0.15 then
						-- Minecraft swings anew every 3 ticks while breaking; the mannequin in Minecraft swings along
						mining.swungAt = now
						swingArm()
						if now - (mining.toldAt or -math.huge) >= 0.25 then
							mining.toldAt = now
							swingRemote:FireServer()
						end
					end
					if mining.progress >= 1 then
						editRemote:FireServer("break", mining.x, mining.y, mining.z, editInfo())
						stopMining()
						breakDelay = REPEAT_BREAK
					else
						showCracks(target, math.floor(mining.progress * 10) - 1) -- Minecraft: stage 0 from 10 %
					end
				end
			end
		elseif mining then
			stopMining()
		end
		if held["break"] and mode == "creative" and now - held["break"] >= REPEAT_BREAK then
			held["break"] = now
			act("break", true)
		end
		if charging then
			local camera = workspace.CurrentCamera
			if not held.use then
				stopCharging(true) -- (let go: shoot)
			elseif not hotbarStack(selected) or hotbarStack(selected).id ~= charging.id or selected ~= charging.slot then
				stopCharging(false)
			elseif camera and not charging.block then
				chargeFov = chargeFov or camera.FieldOfView
				local pull = math.clamp((now - charging.started) / charging.full, 0, 1)
				camera.FieldOfView = (chargeFov :: number) * (1 - 0.15 * pull * pull)
			end
		elseif eating then
			if not held.use or not hotbarStack(selected) or hotbarStack(selected).id ~= eating.id then
				stopEating()
			elseif now - eating.started >= eating.duration then
				-- done: Minecraft eats it (food, effects, bowl / bottle); holding on eats the next one
				inventoryRemote:FireServer("eat", selected - 1)
				stopEating()
				held.use = now + 0.2
			elseif now - eating.crumbsAt >= 0.2 then
				eating.crumbsAt = now
				local eye, look = eyeAndLook()
				local icon = iconContent(eating.id)
				if eye and look and icon and eating.use == "eat" then
					for _ = 1, 3 do
						spawnParticle("", eye + look * 1.2 - Vector3.new(0, 0.6, 0), Vector3.new(math.random() - 0.5, 1, math.random() - 0.5) * 3,
							0.5, 0.15, nil, 25, icon)
					end
				end
			end
		elseif held.use and now - held.use >= REPEAT_USE then
			held.use = now
			if targetMob ~= nil and not eating and not charging then
				-- a right click on a mob: Minecraft's interaction (trading, milking, shearing, feeding ...)
				attackRemote:FireServer(nil, { use = true }, targetMob)
			elseif not startEating() and not startCharging() then
				act("use", true)
			end
		end
		if inventoryOpen then
			UserInputService.MouseBehavior = Enum.MouseBehavior.Default
			UserInputService.MouseIconEnabled = true
			local mouse = UserInputService:GetMouseLocation()
			cursorFrame.Position = UDim2.fromOffset(mouse.X, mouse.Y)
			local stack = if hovered then hovered() else nil
			local carried = cursorFrame.Visible
			hoverName.Visible = stack ~= nil and not carried
			if stack then
				hoverName.Text = "  " .. tostring(stack.name or stack.id) .. "  "
				hoverName.Position = UDim2.fromOffset(mouse.X + 14, mouse.Y - 30)
			end
		end
		-- the item name above the hotbar fades out after 2 s (like Minecraft)
		local age = now - nameShownAt
		itemName.TextTransparency = if age < 1.5 then 0 elseif age < 2 then (age - 1.5) * 2 else 1
	end)
end
-- endregion


-- region items lying in the world (Minecraft's item entities - the server puts an invisible part where each lies)
local FACE_NORMALS, itemPiece, flying, rebuildUnknownItems
do -- (its own block: these locals do not count towards the 200 of the script)
	--[[
		Drawn like Minecraft: blocks as small cubes / models (a quarter of a block), flat items (redstone, sticks, tools)
		as a picture half a block big; turning slowly (1 radian per second), bobbing (0.1 blocks), more copies for bigger
		stacks (2-16: 2, up to 32: 3, up to 48: 4, more: 5). Picked up (by anybody - Minecraft decides who, once): the
		item flies to whoever is closest and is gone.
	]]
	FACE_NORMALS = { up = Enum.NormalId.Top, down = Enum.NormalId.Bottom, north = Enum.NormalId.Front,
		south = Enum.NormalId.Back, east = Enum.NormalId.Right, west = Enum.NormalId.Left }
	local COPY_OFFSETS = { Vector3.new(0, 0, 0), Vector3.new(0.09, 0.05, -0.07), Vector3.new(-0.08, 0.1, 0.06),
		Vector3.new(0.06, 0.15, 0.09), Vector3.new(-0.07, 0.2, -0.08) } -- (blocks)

	local itemVisuals = {} -- anchor part -> visual
	local visualHolder = Instance.new("Folder")
	visualHolder.Name = "MinecraftItemVisuals"
	visualHolder.Parent = workspace -- (made by this client: only here; the pictures come like the world's)

	local function pieceFaceSize(size: Vector3, normal: Enum.NormalId): (number, number)
		if normal == Enum.NormalId.Top or normal == Enum.NormalId.Bottom then
			return size.X, size.Z
		elseif normal == Enum.NormalId.Left or normal == Enum.NormalId.Right then
			return size.Z, size.Y
		end
		return size.X, size.Y
	end

	function itemPiece(parent: Instance, size: Vector3, cframe: CFrame, faces: { [string]: string })
		local part = Instance.new("Part")
		part.Name = "ItemPiece"
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.CastShadow = false
		part.Transparency = 1
		part.Size = Vector3.new(math.max(size.X, 0.02), math.max(size.Y, 0.02), math.max(size.Z, 0.02))
		part.CFrame = cframe
		for direction, key in pairs(faces) do
			local normal = FACE_NORMALS[direction]
			if normal then
				local texture = Instance.new("Texture")
				texture.Face = normal
				local u, v = pieceFaceSize(part.Size, normal)
				texture.StudsPerTileU = u
				texture.StudsPerTileV = v
				texture:SetAttribute("McTexture", key) -- (the picture comes like the world's: applyTexture)
				texture.Parent = part
			end
		end
		part.Parent = parent
	end

	-- one copy of the item around the origin; returns whether it is flat
	local function buildItemShape(parent: Instance, id: string, offset: Vector3): boolean
		local scale = assets and assets.scale or 3
		local item = itemInfo(id)
		local look = item and assets and assets.blocks and (assets.blocks[item.look or ""] or assets.blocks[item.block or ""])
		if look and look.cube and type(look.faces) == "table" then
			itemPiece(parent, Vector3.one * scale * 0.25, CFrame.new(offset * scale), look.faces)
			return false
		elseif look and look.model and type(look.parts) == "table" then
			local unit = scale / 16 * 0.25
			for _, piece in ipairs(look.parts) do
				if type(piece.b) == "table" then
					local b = piece.b
					local center = Vector3.new((b[1] + b[4]) / 2 - 8, (b[2] + b[5]) / 2 - 8, (b[3] + b[6]) / 2 - 8) * unit
					itemPiece(parent, Vector3.new(b[4] - b[1], b[5] - b[2], b[6] - b[3]) * unit,
						CFrame.new(center + offset * scale), piece.f or {})
				elseif type(piece.c) == "table" and type(piece.s) == "table" and type(piece.r) == "table" then
					local c, size, r = piece.c, piece.s, piece.r
					itemPiece(parent, Vector3.new(size[1], size[2], size[3]) * unit,
						CFrame.new(Vector3.new(c[1] - 8, c[2] - 8, c[3] - 8) * unit + offset * scale)
							* CFrame.new(0, 0, 0, r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]), piece.f or {})
				end
			end
			return false
		elseif item and type(item.icon) == "string" then
			itemPiece(parent, Vector3.new(scale * 0.5, scale * 0.5, 0.02), CFrame.new(Vector3.new(0, 0, offset.Z) * scale),
				{ north = item.icon, south = item.icon })
			return true
		end
		-- not known yet (its picture is on the way): a small grey cube
		local part = Instance.new("Part")
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Size = Vector3.one * scale * 0.25
		part.Color = Color3.fromRGB(150, 150, 150)
		part.CFrame = CFrame.new(offset * scale)
		part.Parent = parent
		return false
	end

	local function renderedCopies(count: number): number
		return if count <= 1 then 1 elseif count <= 16 then 2 elseif count <= 32 then 3 elseif count <= 48 then 4 else 5
	end

	local function buildItemVisual(anchor: BasePart)
		local old = itemVisuals[anchor]
		local id = anchor:GetAttribute("McItem")
		local count = tonumber(anchor:GetAttribute("McCount")) or 1
		if type(id) ~= "string" then
			return
		end
		local model = Instance.new("Model")
		model.Name = id
		local flat = false
		for copy = 1, renderedCopies(count) do
			flat = buildItemShape(model, id, COPY_OFFSETS[copy])
		end
		model.WorldPivot = CFrame.new()
		model.Parent = visualHolder
		local visual = {
			model = model, id = id, count = count, flat = flat, known = itemInfo(id) ~= nil,
			position = if old then old.position else anchor.Position,
			born = if old then old.born else os.clock(),
			bob = if old then old.bob else math.random() * math.pi * 2,
		}
		if old then
			old.model:Destroy()
		end
		itemVisuals[anchor] = visual
	end

	-- picked up: it flies to the nearest player (Roblox character or Minecraft player) within 3 blocks, then it is gone
	flying = {}
	local function itemGone(anchor: Instance)
		local visual = itemVisuals[anchor]
		itemVisuals[anchor] = nil
		if not visual then
			return
		end
		local scale = assets and assets.scale or 3
		local best, bestDistance = nil, 3 * scale
		local function consider(model: Instance)
			local root = model:FindFirstChild("HumanoidRootPart")
			if root and root:IsA("BasePart") then
				local distance = (root.Position - visual.position).Magnitude
				if distance < bestDistance then
					best, bestDistance = root, distance
				end
			end
		end
		for _, other in ipairs(Players:GetPlayers()) do
			if other.Character then
				consider(other.Character)
			end
		end
		local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
		for _, folder in ipairs(npcs and npcs:GetChildren() or {}) do
			for _, model in ipairs(folder:GetChildren()) do
				consider(model)
			end
		end
		if best then
			table.insert(flying, { visual = visual, from = visual.position, to = best, started = os.clock() })
		else
			visual.model:Destroy()
		end
	end

	local function watchItems(folder: Instance)
		local function added(anchor: Instance)
			if anchor:IsA("BasePart") then
				buildItemVisual(anchor)
				anchor:GetAttributeChangedSignal("McCount"):Connect(function()
					local visual = itemVisuals[anchor]
					local count = tonumber(anchor:GetAttribute("McCount")) or 1
					if visual and renderedCopies(count) ~= renderedCopies(visual.count) then
						buildItemVisual(anchor)
					elseif visual then
						visual.count = count
					end
				end)
			end
		end
		folder.ChildAdded:Connect(added)
		folder.ChildRemoved:Connect(itemGone)
		for _, anchor in ipairs(folder:GetChildren()) do
			added(anchor)
		end
	end
	task.spawn(function()
		watchItems(workspace:WaitForChild("MinecraftItems"))
	end)

	-- items whose picture came later get drawn again
	function rebuildUnknownItems()
		for anchor, visual in pairs(itemVisuals) do
			if not visual.known and itemInfo(visual.id) then
				buildItemVisual(anchor)
			end
		end
	end

	RunService.RenderStepped:Connect(function(dt)
		local scale = assets and assets.scale or 3
		local now = os.clock()
		local follow = 1 - math.exp(-dt * 12)
		for anchor, visual in pairs(itemVisuals) do
			visual.position = visual.position:Lerp(anchor.Position, follow)
			local age = now - visual.born
			local bob = (math.sin(age * 2 + visual.bob) * 0.1 + 0.1) * scale -- Minecraft: sin(age / 10 ticks) * 0.1 + 0.1
			local lift = (if visual.flat then 0.25 else 0.125) * scale
			visual.model:PivotTo(CFrame.new(visual.position + Vector3.new(0, bob + lift, 0)) * CFrame.Angles(0, age + visual.bob, 0))
		end
		for index = #flying, 1, -1 do
			local entry = flying[index]
			local alpha = math.min(1, (now - entry.started) / 0.15) -- Minecraft: 3 ticks
			local target = if entry.to.Parent then entry.to.Position else entry.from
			entry.visual.model:PivotTo(CFrame.new(entry.from:Lerp(target, alpha)))
			if alpha >= 1 then
				entry.visual.model:Destroy()
				table.remove(flying, index)
			end
		end
	end)
end
-- endregion

-- region preparing the icons: all at once in the background (the inventory then shows every icon right away)
local preloadIcons
do -- (its own block: these locals do not count towards the 200 of the script)
	local preloading, preloadAgain = false, false
	function preloadIcons()
		if preloading then
			preloadAgain = true -- (more items came while making them: once more at the end)
			return
		end
		if not assets then
			return
		end
		preloading = true
		task.spawn(function()
			repeat
				preloadAgain = false
				local started = os.clock()
				for _, item in ipairs(assets and assets.items or {}) do
					if type(item) == "table" and itemInfo(item.id) then
						iconContent(item.id)
					end
					if os.clock() - started > 0.004 then
						task.wait() -- (at most 4 ms per frame - no stutter)
						started = os.clock()
					end
				end
			until not preloadAgain
			preloading = false
			refresh()
		end)
	end
end
-- endregion

-- region settings (M): field of view + shaders - only for this player, nothing goes to Minecraft or the others
local Shaders, label
do -- (its own block: these locals do not count towards the 200 of the script)
	local refreshMenu -- below
	Shaders = require(ReplicatedStorage:WaitForChild("MinecraftShaders") :: any)
	local settings = { fov = 70, shader = "off" }
	local menuOpen = false
	local menuPage = "main"

	local menu = Instance.new("Frame")
	menu.Name = "Settings"
	menu.BackgroundColor3 = Color3.new(0, 0, 0)
	menu.BackgroundTransparency = 0.35
	menu.Size = UDim2.fromScale(1, 1)
	menu.Visible = false
	menu.ZIndex = 40
	menu.Parent = screen
	local panel = Instance.new("Frame")
	panel.Name = "Panel"
	panel.AnchorPoint = Vector2.new(0.5, 0.5)
	panel.Position = UDim2.fromScale(0.5, 0.5)
	panel.Size = UDim2.fromOffset(310, 200)
	panel.BackgroundTransparency = 1
	panel.ZIndex = 41
	panel.Parent = menu
	scaled(panel)

	function label(parent: Instance, text: string, y: number, color: Color3?): TextLabel
		local item = Instance.new("TextLabel")
		item.BackgroundTransparency = 1
		item.Position = UDim2.fromOffset(0, y)
		item.Size = UDim2.new(1, 0, 0, 10)
		item.Font = Enum.Font.Arcade
		item.TextSize = 9
		item.Text = text
		item.TextColor3 = color or Color3.new(1, 1, 1)
		item.TextStrokeTransparency = 0.5
		item.ZIndex = 43
		item.Parent = parent
		return item
	end

	-- A Minecraft button (its own picture, 9-slice like Minecraft draws it), x / y / w in Minecraft pixels
	local buttons = {}
	local function button(parent: Instance, text: string, x: number, y: number, w: number, onClick: () -> ())
		local back = image(parent, "Button", x, y, w, 20, 42)
		back.ScaleType = Enum.ScaleType.Slice
		back.SliceCenter = Rect.new(3, 3, 197, 17)
		back.BackgroundColor3 = Color3.fromRGB(110, 110, 110)
		back.BorderSizePixel = 0
		local click = Instance.new("TextButton")
		click.BackgroundTransparency = 1
		click.Size = UDim2.fromScale(1, 1)
		click.Font = Enum.Font.Arcade
		click.TextSize = 9
		click.Text = text
		click.TextColor3 = Color3.new(1, 1, 1)
		click.TextStrokeTransparency = 0.5
		click.ZIndex = 44
		click.Parent = back
		local entry = { back = back, click = click, hover = false }
		click.MouseEnter:Connect(function()
			entry.hover = true
			refreshMenu()
		end)
		click.MouseLeave:Connect(function()
			entry.hover = false
			refreshMenu()
		end)
		click.MouseButton1Click:Connect(onClick)
		table.insert(buttons, entry)
		return entry
	end

	local mainPage = Instance.new("Frame")
	mainPage.BackgroundTransparency = 1
	mainPage.Size = UDim2.fromScale(1, 1)
	mainPage.ZIndex = 41
	mainPage.Parent = panel
	local shaderPage = mainPage:Clone()
	shaderPage.Parent = panel
	label(mainPage, "Optionen", 0)
	label(shaderPage, "Shader", 0)
	local shaderHint = label(shaderPage, "", 110, Color3.fromRGB(170, 170, 170))

	-- the field of view slider (Minecraft: 30 .. 110, "Normal" = 70)
	local slider = image(mainPage, "Fov", 55, 30, 200, 20, 42)
	slider.ScaleType = Enum.ScaleType.Slice
	slider.SliceCenter = Rect.new(3, 3, 197, 17)
	slider.BackgroundColor3 = Color3.fromRGB(60, 60, 60)
	slider.BorderSizePixel = 0
	local handle = image(slider, "Handle", 0, 0, 8, 20, 43)
	handle.ScaleType = Enum.ScaleType.Slice
	handle.SliceCenter = Rect.new(2, 2, 6, 17)
	handle.BackgroundColor3 = Color3.fromRGB(190, 190, 190)
	handle.BorderSizePixel = 0
	local sliderText = label(slider, "", 5, nil)
	local dragging = false
	local sliderHover = false

	local function fovText(value: number): string
		if value == 70 then
			return "Sichtfeld: Normal"
		elseif value == 110 then
			return "Sichtfeld: Quake Pro"
		end
		return "Sichtfeld: " .. tostring(value)
	end

	local shaderButtons = {}

	refreshMenu = function()
		menu.Visible = menuOpen
		mainPage.Visible = menuPage == "main"
		shaderPage.Visible = menuPage == "shaders"
		local normal, highlighted = gui("button"), gui("button_highlighted")
		for _, entry in ipairs(buttons) do
			local picture = if entry.hover then highlighted or normal else normal
			setPicture(entry.back, picture)
			entry.back.BackgroundTransparency = if picture then 1 else (if entry.hover then 0.1 else 0.3)
		end
		local sliderPicture = gui("slider")
		setPicture(slider, sliderPicture)
		slider.BackgroundTransparency = if sliderPicture then 1 else 0.3
		local handlePicture = if sliderHover or dragging then gui("slider_handle_highlighted") or gui("slider_handle")
			else gui("slider_handle")
		setPicture(handle, handlePicture)
		handle.BackgroundTransparency = if handlePicture then 1 else 0
		handle.Position = UDim2.fromOffset(math.floor((settings.fov - 30) / 80 * 192 + 0.5), 0)
		sliderText.Text = fovText(settings.fov)
		for id, entry in pairs(shaderButtons) do
			local name = entry.name
			entry.click.Text = if settings.shader == id then "> " .. name .. " <" else name
			if entry.hover then
				shaderHint.Text = entry.description
			end
		end
		if not next(shaderButtons) or not (function()
			for _, entry in pairs(shaderButtons) do
				if entry.hover then
					return true
				end
			end
			return false
		end)() then
			for _, shader in ipairs(Shaders.LIST) do
				if shader.id == settings.shader then
					shaderHint.Text = shader.description
				end
			end
		end
	end

	local function setFov(mouseX: number)
		local left = slider.AbsolutePosition.X
		local width = math.max(slider.AbsoluteSize.X, 1)
		local value = math.clamp(math.floor(30 + (mouseX - left) / width * 80 + 0.5), 30, 110)
		if value ~= settings.fov then
			settings.fov = value
			player:SetAttribute("McFov", value) -- MinecraftPlayer uses it for the camera
		end
		refreshMenu()
	end

	local sliderButton = Instance.new("TextButton")
	sliderButton.BackgroundTransparency = 1
	sliderButton.Text = ""
	sliderButton.Size = UDim2.fromScale(1, 1)
	sliderButton.ZIndex = 45
	sliderButton.Parent = slider
	sliderButton.MouseButton1Down:Connect(function(x)
		dragging = true
		setFov(x)
	end)
	sliderButton.MouseEnter:Connect(function()
		sliderHover = true
		refreshMenu()
	end)
	sliderButton.MouseLeave:Connect(function()
		sliderHover = false
		refreshMenu()
	end)
	UserInputService.InputChanged:Connect(function(input)
		if dragging and input.UserInputType == Enum.UserInputType.MouseMovement then
			setFov(input.Position.X)
		end
	end)
	UserInputService.InputEnded:Connect(function(input)
		if input.UserInputType == Enum.UserInputType.MouseButton1 and dragging then
			dragging = false
			refreshMenu()
		end
	end)

	local function setMenu(open: boolean)
		menuOpen = open
		menuPage = "main"
		player:SetAttribute("McMenuOpen", open) -- MinecraftPlayer frees the mouse and stops walking
		refreshMenu()
	end

	button(mainPage, "Shader ...", 55, 60, 200, function()
		menuPage = "shaders"
		refreshMenu()
	end)
	button(mainPage, "Fertig", 55, 120, 200, function()
		setMenu(false)
	end)
	for index, shader in ipairs(Shaders.LIST) do
		local entry = button(shaderPage, shader.name, 55, 20 + index * 24, 200, function()
			settings.shader = shader.id
			Shaders.apply(shader.id)
			refreshMenu()
		end)
		entry.name = shader.name
		entry.description = shader.description
		shaderButtons[shader.id] = entry
	end
	button(shaderPage, "Fertig", 55, 130, 200, function()
		menuPage = "main"
		refreshMenu()
	end)

	UserInputService.InputBegan:Connect(function(input, processed)
		if processed or inventoryOpen or input.KeyCode ~= Enum.KeyCode.M then
			return
		end
		setMenu(not menuOpen)
	end)
	RunService.RenderStepped:Connect(function()
		if menuOpen then
			UserInputService.MouseBehavior = Enum.MouseBehavior.Default
			UserInputService.MouseIconEnabled = true
		end
	end)
end
-- endregion

-- region health: hearts, fall damage, getting hit
do -- (its own block: these locals do not count towards the 200 of the script)
	local hearts = {}
	for index = 1, 10 do
		local x = (index - 1) * 8
		local container = image(hotbar, "Heart" .. index, x, -17, 9, 9, 4)
		local fill = image(container, "Fill", 0, 0, 9, 9, 5)
		hearts[index] = { container = container, fill = fill }
	end
	local hurtAt = -math.huge
	local hurtRoll = 0
	local flash = Instance.new("Frame")
	flash.Name = "Hurt"
	flash.BackgroundColor3 = Color3.fromRGB(255, 0, 0)
	flash.BackgroundTransparency = 1
	flash.BorderSizePixel = 0
	flash.Size = UDim2.fromScale(1, 1)
	flash.ZIndex = 0
	flash.Parent = screen

	-- the drumsticks on the right above the hotbar (Minecraft: food 20 = 10 drumsticks; they shake with no saturation)
	local foods = {}
	for index = 1, 10 do
		local x = 182 - (index - 1) * 8 - 9
		local container = image(hotbar, "Food" .. index, x, -17, 9, 9, 4)
		local fill = image(container, "Fill", 0, 0, 9, 9, 5)
		foods[index] = { container = container, fill = fill, x = x }
	end
	local function updateFood(survival: boolean)
		for _, food in ipairs(foods) do
			food.container.Visible = survival
		end
		if not survival then
			return
		end
		local level = tonumber(player:GetAttribute("McFood")) or 20
		local saturation = tonumber(player:GetAttribute("McSaturation")) or 5
		local hungry = string.find(tostring(player:GetAttribute("McEffects") or ""), '"hunger"', 1, true) ~= nil
		local empty = gui(if hungry then "food_empty_hunger" else "food_empty")
		local full = gui(if hungry then "food_full_hunger" else "food_full")
		local half = gui(if hungry then "food_half_hunger" else "food_half")
		local tick = math.floor(os.clock() * 20)
		for index, food in ipairs(foods) do
			local points = level - (index - 1) * 2
			setPicture(food.container, empty)
			setPicture(food.fill, if points >= 2 then full elseif points == 1 then half else nil)
			local shake = if saturation <= 0 and tick % (level * 3 + 1) == 0 then math.random(-1, 1) else 0
			food.container.Position = UDim2.fromOffset(food.x, -17 + shake)
			food.container.BackgroundTransparency = if empty then 1 else 0.6
			food.container.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
			food.fill.BackgroundTransparency = if full or points < 1 then 1 else 0
			food.fill.BackgroundColor3 = Color3.fromRGB(190, 120, 50)
		end
	end

	-- the armor row above the hearts (Minecraft: only with armor, 20 points = 10 chestplates) and the experience bar
	-- between hearts and hotbar with the level in green (Gui.renderExperienceBar / renderArmor)
	local armors = {}
	for index = 1, 10 do
		armors[index] = image(hotbar, "Armor" .. index, (index - 1) * 8, -27, 9, 9, 4)
	end
	local xpBack = image(hotbar, "Experience", 0, -7, 182, 5, 3)
	local xpClip = Instance.new("Frame")
	xpClip.Name = "Progress"
	xpClip.BackgroundTransparency = 1
	xpClip.ClipsDescendants = true
	xpClip.Size = UDim2.fromOffset(0, 5)
	xpClip.ZIndex = 4
	xpClip.Parent = xpBack
	local xpFill = image(xpClip, "Fill", 0, 0, 182, 5, 4)
	local xpLevel = Instance.new("TextLabel")
	xpLevel.Name = "Level"
	xpLevel.BackgroundTransparency = 1
	xpLevel.AnchorPoint = Vector2.new(0.5, 1)
	xpLevel.Position = UDim2.new(0.5, 0, 0, -4)
	xpLevel.Size = UDim2.fromOffset(40, 9)
	xpLevel.Font = Enum.Font.Arcade
	xpLevel.TextSize = 9
	xpLevel.TextColor3 = Color3.fromRGB(128, 255, 32)
	xpLevel.TextStrokeColor3 = Color3.new(0, 0, 0)
	xpLevel.TextStrokeTransparency = 0
	xpLevel.ZIndex = 6
	xpLevel.Parent = hotbar
	local function updateArmorAndXp(survival: boolean)
		local armor = math.floor(tonumber(player:GetAttribute("McArmor")) or 0)
		local empty, full, half = gui("armor_empty"), gui("armor_full"), gui("armor_half")
		for index, label in ipairs(armors) do
			label.Visible = survival and armor > 0
			local points = armor - (index - 1) * 2
			setPicture(label, if points >= 2 then full elseif points == 1 then half else empty)
			label.BackgroundTransparency = if full then 1 else 0.5
			label.BackgroundColor3 = if points >= 1 then Color3.fromRGB(200, 200, 210) else Color3.fromRGB(40, 40, 40)
		end
		local level = math.floor(tonumber(player:GetAttribute("McXpLevel")) or 0)
		local progress = math.clamp(tonumber(player:GetAttribute("McXpProgress")) or 0, 0, 1)
		xpBack.Visible = survival
		setPicture(xpBack, gui("experience_bar_background"))
		setPicture(xpFill, gui("experience_bar_progress"))
		xpBack.BackgroundTransparency = if gui("experience_bar_background") then 1 else 0.5
		xpBack.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
		xpFill.BackgroundTransparency = if gui("experience_bar_progress") then 1 else 0
		xpFill.BackgroundColor3 = Color3.fromRGB(128, 255, 32)
		xpClip.Size = UDim2.fromOffset(math.floor(progress * 183), 5)
		xpLevel.Visible = survival and level > 0
		xpLevel.Text = tostring(level)
	end

	-- region titles: Minecraft's /title (title + subtitle in the middle, the action bar above the hotbar) - Gui.renderTitle:
	-- fade in / stay / fade out in ticks (default 10 / 70 / 20), the title 4x, the subtitle 2x, the action bar 3 s
	local titleRemote = remotes:WaitForChild("Title", 10) :: RemoteEvent?
	local titleFrame = Instance.new("Frame")
	titleFrame.Name = "Title"
	titleFrame.BackgroundTransparency = 1
	titleFrame.AnchorPoint = Vector2.new(0.5, 0.5)
	titleFrame.Position = UDim2.fromScale(0.5, 0.42)
	titleFrame.Size = UDim2.fromOffset(400, 80)
	titleFrame.Parent = screen
	scaled(titleFrame)
	local function titleLabel(name: string, y: number, size: number): TextLabel
		local label = Instance.new("TextLabel")
		label.Name = name
		label.BackgroundTransparency = 1
		label.AnchorPoint = Vector2.new(0.5, 0)
		label.Position = UDim2.new(0.5, 0, 0, y)
		label.Size = UDim2.fromOffset(400, size)
		label.Font = Enum.Font.Arcade
		label.TextSize = size
		label.TextColor3 = Color3.new(1, 1, 1)
		label.TextStrokeColor3 = Color3.fromRGB(63, 63, 63)
		label.TextStrokeTransparency = 0
		label.TextTransparency = 1
		label.TextStrokeTransparency = 1
		label.ZIndex = 20
		label.Parent = titleFrame
		return label
	end
	local titleText = titleLabel("Big", 0, 36)
	local subtitleText = titleLabel("Small", 42, 18)
	local actionBar = Instance.new("TextLabel")
	actionBar.Name = "ActionBar"
	actionBar.BackgroundTransparency = 1
	actionBar.AnchorPoint = Vector2.new(0.5, 1)
	actionBar.Position = UDim2.new(0.5, 0, 0, -46)
	actionBar.Size = UDim2.fromOffset(300, 10)
	actionBar.Font = Enum.Font.Arcade
	actionBar.TextSize = 9
	actionBar.TextColor3 = Color3.new(1, 1, 1)
	actionBar.TextStrokeTransparency = 1
	actionBar.TextTransparency = 1
	actionBar.ZIndex = 20
	actionBar.Parent = hotbar
	local titleTimes = { fadeIn = 10, stay = 70, fadeOut = 20 }
	local titleAt = -math.huge
	local actionAt = -math.huge
	local pendingSubtitle = ""
	local function colorOf(value: number?): Color3
		if type(value) == "number" then
			return Color3.fromRGB(bit32.band(bit32.rshift(value, 16), 255), bit32.band(bit32.rshift(value, 8), 255), bit32.band(value, 255))
		end
		return Color3.new(1, 1, 1)
	end
	if titleRemote then
		titleRemote.OnClientEvent:Connect(function(data)
			if type(data) ~= "table" then
				return
			end
			if data.kind == "title" then
				titleText.Text = tostring(data.text or "")
				titleText.TextColor3 = colorOf(data.color)
				subtitleText.Text = pendingSubtitle
				pendingSubtitle = ""
				titleAt = os.clock()
			elseif data.kind == "subtitle" then
				pendingSubtitle = tostring(data.text or "") -- (Minecraft: shown with the next title)
				if os.clock() - titleAt < (titleTimes.fadeIn + titleTimes.stay) / 20 then
					subtitleText.Text = pendingSubtitle
					subtitleText.TextColor3 = colorOf(data.color)
				end
			elseif data.kind == "actionbar" then
				actionBar.Text = tostring(data.text or "")
				actionBar.TextColor3 = colorOf(data.color)
				actionAt = os.clock()
			elseif data.kind == "times" then
				titleTimes = { fadeIn = tonumber(data.fadeIn) or 10, stay = tonumber(data.stay) or 70, fadeOut = tonumber(data.fadeOut) or 20 }
			elseif data.kind == "clear" then
				titleAt = -math.huge
				if data.reset then
					titleTimes = { fadeIn = 10, stay = 70, fadeOut = 20 }
				end
			end
		end)
	end
	local function updateTitles()
		local t = (os.clock() - titleAt) * 20
		local alpha = 0
		if t < titleTimes.fadeIn then
			alpha = t / math.max(1, titleTimes.fadeIn)
		elseif t < titleTimes.fadeIn + titleTimes.stay then
			alpha = 1
		elseif t < titleTimes.fadeIn + titleTimes.stay + titleTimes.fadeOut then
			alpha = 1 - (t - titleTimes.fadeIn - titleTimes.stay) / math.max(1, titleTimes.fadeOut)
		end
		for _, label in ipairs({ titleText, subtitleText }) do
			label.TextTransparency = 1 - alpha
			label.TextStrokeTransparency = 1 - alpha * 0.8
		end
		local a = os.clock() - actionAt
		local actionAlpha = if a < 2.5 then 1 elseif a < 3 then (3 - a) / 0.5 else 0
		actionBar.TextTransparency = 1 - actionAlpha
		actionBar.TextStrokeTransparency = 1 - actionAlpha * 0.6
	end
	-- endregion

	-- burning (lava, fire - attribute McBurning on his character): Minecraft's flames at the bottom of the screen
	local burningOverlay = Instance.new("Frame")
	burningOverlay.Name = "Burning"
	burningOverlay.AnchorPoint = Vector2.new(0, 1)
	burningOverlay.Position = UDim2.fromScale(0, 1)
	burningOverlay.Size = UDim2.fromScale(1, 0.45)
	burningOverlay.BackgroundColor3 = Color3.fromRGB(255, 120, 20)
	burningOverlay.BorderSizePixel = 0
	burningOverlay.Visible = false
	burningOverlay.ZIndex = 0
	burningOverlay.Parent = screen
	local burningGradient = Instance.new("UIGradient")
	burningGradient.Rotation = -90
	burningGradient.Transparency = NumberSequence.new({ NumberSequenceKeypoint.new(0, 0.35), NumberSequenceKeypoint.new(1, 1) })
	burningGradient.Color = ColorSequence.new(Color3.fromRGB(255, 200, 60), Color3.fromRGB(230, 60, 10))
	burningGradient.Parent = burningOverlay
	local function updateBurning()
		local character = player.Character
		local burning = character ~= nil and character:GetAttribute("McBurning") == true
		burningOverlay.Visible = burning
		if burning then
			local flicker = 0.35 + 0.12 * math.sin(os.clock() * 23) + 0.06 * math.sin(os.clock() * 41)
			burningGradient.Transparency = NumberSequence.new({ NumberSequenceKeypoint.new(0, flicker), NumberSequenceKeypoint.new(1, 1) })
		end
	end

	local function updateHearts()
		updateBurning()
		updateTitles()
		local mode = gameMode()
		local survival = mode == "survival" or mode == "adventure" -- (creative / spectator: no hearts, like Minecraft)
		for _, heart in ipairs(hearts) do
			heart.container.Visible = survival
		end
		updateFood(survival)
		updateArmorAndXp(survival)
		if not survival then
			return
		end
		local character = player.Character
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		local health = if humanoid then math.max(humanoid.Health, 0) else 0
		local blinking = os.clock() - hurtAt < 0.6 and math.floor((os.clock() - hurtAt) * 10) % 2 == 0
		local container = gui(if blinking then "heart_container_blinking" else "heart_container") or gui("heart_container")
		local full, half = gui("heart_full"), gui("heart_half")
		for index, heart in ipairs(hearts) do
			local points = health - (index - 1) * 2 -- 2 health per heart
			setPicture(heart.container, container)
			setPicture(heart.fill, if points >= 1.5 then full elseif points >= 0.5 then half else nil)
			-- without Minecraft's pictures: small red squares
			heart.container.BackgroundTransparency = if container then 1 else 0.6
			heart.container.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
			heart.fill.BackgroundTransparency = if full or points < 0.5 then 1 else 0
			heart.fill.BackgroundColor3 = Color3.fromRGB(220, 30, 30)
			heart.fill.Size = UDim2.fromOffset(if not full and points < 1.5 then 4 else 9, 9)
		end
	end

	--[[
		Air under water like Minecraft (LivingEntity.baseTick + Hud.extractAirBubbles): 300 ticks of air, 1 per tick with the
		eyes in water (survival / adventure), 4 back per tick outside; at -20: 2 damage (Drown) and 0 again. 10 bubbles on
		the right, one row above the food row: full, popping (the one that just went), empty.
	]]
	local AIR_MAX = 300
	local airSupply = AIR_MAX
	local airClock = 0
	local bubbles = {}
	for index = 1, 10 do
		bubbles[index] = image(hotbar, "Air" .. index, 182 - (index - 1) * 8 - 9, -17 - 10, 9, 9, 4)
	end
	local random = Random.new()
	local airTicks = 0

	local function airBubble(air: number, delta: number): number
		return math.ceil((air + delta) * 10 / AIR_MAX)
	end

	local function airStep(dt: number)
		local mode = gameMode()
		local survival = mode == "survival" or mode == "adventure"
		local underwater = player:GetAttribute("McEyeInWater") == true
		local character = player.Character
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		airClock += dt
		while airClock >= 0.05 do
			airClock -= 0.05
			airTicks += 1
			if underwater then
				if survival and humanoid and humanoid.Health > 0 then
					airSupply -= 1
					if airSupply <= -20 then
						airSupply = 0
						drownRemote:FireServer() -- (the server checks the head is in water, Minecraft: 2 damage)
					end
				end
			elseif airSupply < AIR_MAX then
				airSupply = math.min(airSupply + 4, AIR_MAX)
			end
		end
		local air = math.clamp(airSupply, 0, AIR_MAX)
		local shown = survival and (underwater or air < AIR_MAX)
		local full = airBubble(air, -2)
		local popping = airBubble(air, 0)
		local empty = 10 - airBubble(air, if air == 0 or not underwater then 0 else 1)
		local fullPicture, burstPicture, emptyPicture = gui("air"), gui("air_bursting"), gui("air_empty")
		for index, bubble in ipairs(bubbles) do
			bubble.Visible = shown
			if not shown then
				continue
			end
			local picture, jitter = nil, 0
			if index <= full then
				picture = fullPicture
			elseif full ~= popping and index == popping and underwater then
				picture = burstPicture
			elseif index > 10 - empty then
				picture = emptyPicture
				if empty == 10 and airTicks % 2 == 0 then
					jitter = random:NextInteger(0, 1) -- (Minecraft: the empty row shakes when the air is out)
				end
			end
			setPicture(bubble, picture)
			bubble.Position = UDim2.fromOffset(182 - (index - 1) * 8 - 9, -27 + jitter)
			bubble.BackgroundTransparency = if picture or not fullPicture then 1 else 1
		end
	end
	player.CharacterAdded:Connect(function()
		airSupply = AIR_MAX
	end)

	-- Minecraft's fall damage: the server hurts 1 per block over 3
	local fallPeak = nil
	local fallLastY: number? = nil
	local FALLING = {
		[Enum.HumanoidStateType.Freefall] = true,
		[Enum.HumanoidStateType.Jumping] = true,
		[Enum.HumanoidStateType.FallingDown] = true,
	}
	local function trackFall()
		local character = player.Character
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if not humanoid or not root or humanoid.Health <= 0 then
			fallPeak = nil
			return
		end
		local mode = gameMode()
		if mode == "creative" or mode == "spectator" or player:GetAttribute("McFlying") == true then
			fallPeak = nil -- (no fall damage; flying starts the fall new)
			return
		end
		local effectsText = tostring(player:GetAttribute("McEffects") or "")
		if player:GetAttribute("McFluid") ~= nil or player:GetAttribute("McClimbing") == true or string.find(effectsText, '"slow_falling"', 1, true)
			or string.find(effectsText, '"levitation"', 1, true) then
			fallPeak = nil -- (Minecraft: in water / lava the fall starts new - landing in water does not hurt; slow falling)
			return
		end
		local humanoidState = humanoid:GetState()
		local y = root.Position.Y
		-- a jump of many blocks in one frame (a portal, /tp): no fall - the fall starts new there
		if fallLastY and math.abs(y - fallLastY) > 30 then
			fallPeak = nil
		end
		fallLastY = y
		if FALLING[humanoidState] then
			fallPeak = math.max(fallPeak or y, y)
		elseif fallPeak then
			local blocks = (fallPeak - y) / (assets and assets.scale or 3)
			fallPeak = nil
			if blocks > 3 and humanoidState ~= Enum.HumanoidStateType.Swimming and humanoidState ~= Enum.HumanoidStateType.Climbing then
				fallRemote:FireServer(blocks)
			end
		end
	end
	player.CharacterAdded:Connect(function()
		fallPeak = nil
	end)

	-- Hit (by a Minecraft player or the fall): red flash, the camera tilts, knockback away from the attacker
	hurtRemote.OnClientEvent:Connect(function(amount, from)
		hurtAt = os.clock()
		hurtRoll = 0.18
		flash.BackgroundTransparency = 0.7
		local character = player.Character
		local root = character and character:FindFirstChild("HumanoidRootPart")
		if root and typeof(from) == "Vector3" then
			local away = root.Position - from
			away = Vector3.new(away.X, 0, away.Z)
			if away.Magnitude > 0.01 then
				-- Minecraft's knockback: 0.4 blocks/tick away + up (with Minecraft's gravity about a small hop)
				root.AssemblyLinearVelocity += away.Unit * 24 + Vector3.new(0, 20, 0)
			end
		end
	end)

	RunService:BindToRenderStep("MinecraftHurtCamera", Enum.RenderPriority.Camera.Value + 1, function(dt)
		updateHearts()
		trackFall()
		airStep(dt)
		flash.BackgroundTransparency = math.min(1, flash.BackgroundTransparency + dt * 1.5)
		if hurtRoll > 0.001 then
			local camera = workspace.CurrentCamera
			if camera then
				camera.CFrame *= CFrame.Angles(0, 0, hurtRoll)
			end
			hurtRoll *= math.exp(-dt * 8)
		end
	end)
end
-- endregion

-- region particles (Minecraft's own pictures, drawn as small billboards - only on this client)
local particleRandom, particleBurst
do -- (its own block: these locals do not count towards the 200 of the script)
	--[[
		The server says where ("Particles": kind, position, extra): "crit" (stars when a hit is critical), "magic"
		(enchanted hit), "effect" (the swirl of a status effect, extra = colour), "smoke". Each particle flies, slows down
		and fades like Minecraft's (CritParticle: 0.1 blocks/tick out, gravity, 6-12 ticks).
	]]
	local particleFolder = Instance.new("Folder")
	particleFolder.Name = "MinecraftParticles"
	local particleAnchor = Instance.new("Part")
	particleAnchor.Name = "Anchor"
	particleAnchor.Anchored = true
	particleAnchor.CanCollide = false
	particleAnchor.CanQuery = false
	particleAnchor.CanTouch = false
	particleAnchor.Transparency = 1
	particleAnchor.Size = Vector3.one * 0.05
	particleAnchor.CFrame = CFrame.new()
	particleAnchor.Parent = particleFolder
	local particles = {} -- {gui, image, pos, vel, born, life, gravity, size}
	local MAX_PARTICLES = 200
	particleRandom = Random.new()

	spawnParticle = function(key: string, position: Vector3, velocity: Vector3, life: number, size: number,
		colour: Color3?, gravity: number?, picture: Content?)
		local content = picture or gui(key)
		if not content or #particles >= MAX_PARTICLES then
			return
		end
		if not particleFolder.Parent then
			particleFolder.Parent = workspace.CurrentCamera
		end
		local billboard = Instance.new("BillboardGui")
		billboard.Adornee = particleAnchor
		billboard.AlwaysOnTop = false
		billboard.LightInfluence = 0
		billboard.Size = UDim2.fromScale(size, size)
		billboard.StudsOffsetWorldSpace = position
		local label = Instance.new("ImageLabel")
		label.BackgroundTransparency = 1
		label.Size = UDim2.fromScale(1, 1)
		label.ImageContent = content
		label.ResampleMode = Enum.ResamplerMode.Pixelated
		label.ImageColor3 = colour or Color3.new(1, 1, 1)
		label.Parent = billboard
		billboard.Parent = particleFolder
		table.insert(particles, { gui = billboard, image = label, pos = position, vel = velocity, born = os.clock(), life = life,
			gravity = gravity or 0 })
	end

	function particleBurst(kind: string, at: Vector3, extra: any)
		local block = assets and assets.scale or 3
		if kind == "crit" or kind == "magic" then
			-- Minecraft: 16 particles from the hit entity, out in every direction, a little up
			for _ = 1, 16 do
				local direction = Vector3.new(particleRandom:NextNumber(-1, 1), particleRandom:NextNumber(-0.2, 1),
					particleRandom:NextNumber(-1, 1))
				if direction.Magnitude > 0.01 then
					direction = direction.Unit
				end
				local colour = if kind == "crit" then Color3.fromRGB(255, 255, 255) else Color3.fromRGB(170, 120, 255)
				spawnParticle(if kind == "crit" then "particle_critical_hit" else "particle_enchanted_hit",
					at + direction * 0.3 * block, direction * particleRandom:NextNumber(1.5, 3) * block,
					particleRandom:NextNumber(0.3, 0.6), 0.2 * block, colour, 0.8 * block)
			end
		elseif kind == "effect" then
			local colour = if typeof(extra) == "Color3" then extra else Color3.new(1, 1, 1)
			for _ = 1, 2 do
				local offset = Vector3.new(particleRandom:NextNumber(-0.3, 0.3), particleRandom:NextNumber(0, 1.8),
					particleRandom:NextNumber(-0.3, 0.3)) * block
				spawnParticle("particle_effect_" .. tostring(particleRandom:NextInteger(0, 7)), at + offset,
					Vector3.new(0, 0.4 * block, 0), 1, 0.15 * block, colour, 0)
			end
		elseif kind == "break" then
			-- Minecraft's crumbs of the broken block: little pieces of its picture, flying out and falling
			local picture = if type(extra) == "string" then worldContent(extra) else nil
			if picture then
				for _ = 1, 14 do
					local offset = Vector3.new(particleRandom:NextNumber(-0.4, 0.4), particleRandom:NextNumber(-0.4, 0.4),
						particleRandom:NextNumber(-0.4, 0.4)) * block
					spawnParticle("", at + offset, (offset / block) * 2 * block + Vector3.new(0, 1.2 * block, 0),
						particleRandom:NextNumber(0.4, 0.9), particleRandom:NextNumber(0.08, 0.16) * block, nil, 9 * block, picture)
				end
			end
		elseif kind == "smoke" then
			for _ = 1, 8 do
				local offset = Vector3.new(particleRandom:NextNumber(-0.4, 0.4), particleRandom:NextNumber(0, 0.6),
					particleRandom:NextNumber(-0.4, 0.4)) * block
				spawnParticle("particle_generic_" .. tostring(particleRandom:NextInteger(0, 7)), at + offset,
					Vector3.new(0, 0.3 * block, 0), particleRandom:NextNumber(0.6, 1.2), 0.2 * block, Color3.fromRGB(160, 160, 160), 0)
			end
		end
	end

	RunService.Heartbeat:Connect(function(dt)
		if #particles == 0 then
			return
		end
		local now = os.clock()
		for index = #particles, 1, -1 do
			local particle = particles[index]
			local age = now - particle.born
			if age >= particle.life or not particle.gui.Parent then
				particle.gui:Destroy()
				table.remove(particles, index)
			else
				-- Minecraft: x 0.7 per tick (crits stop quickly), a little gravity
				particle.vel = particle.vel * (0.7 ^ (dt * 20)) - Vector3.new(0, particle.gravity * dt, 0)
				particle.pos += particle.vel * dt
				particle.gui.StudsOffsetWorldSpace = particle.pos
				particle.image.ImageTransparency = math.clamp((age / particle.life - 0.6) / 0.4, 0, 1)
			end
		end
	end)

	local particlesRemote = remotes:WaitForChild("Particles", 10)
	if particlesRemote then
		(particlesRemote :: RemoteEvent).OnClientEvent:Connect(function(kind, at, extra)
			if type(kind) == "string" and typeof(at) == "Vector3" then
				particleBurst(kind, at, extra)
			end
		end)
	end
end
-- endregion

-- region status effects: Minecraft's icons at the top right, the swirl around everybody who has one, invisible players
do -- (its own block: these locals do not count towards the 200 of the script)
	local HttpService = game:GetService("HttpService")
	local function decodeEffects(text: any): { any }
		local ok, decoded = pcall(function()
			return HttpService:JSONDecode(if type(text) == "string" then text else "[]")
		end)
		return if ok and type(decoded) == "table" then decoded else {}
	end
	local myEffects: { any } = {}
	player:GetAttributeChangedSignal("McEffects"):Connect(function()
		myEffects = decodeEffects(player:GetAttribute("McEffects"))
	end)
	myEffects = decodeEffects(player:GetAttribute("McEffects"))

	local effectHud = Instance.new("Frame")
	effectHud.Name = "Effects"
	effectHud.BackgroundTransparency = 1
	effectHud.AnchorPoint = Vector2.new(1, 0)
	effectHud.Position = UDim2.new(1, 0, 0, 0)
	effectHud.Size = UDim2.fromOffset(250, 52)
	effectHud.Parent = screen
	scaled(effectHud)
	local effectSlots = {}
	local function effectSlot(index: number)
		local slot = effectSlots[index]
		if not slot then
			local back = image(effectHud, "Effect" .. index, 0, 0, 24, 24, 5)
			local icon = image(back, "Icon", 3, 3, 18, 18, 6)
			slot = { back = back, icon = icon }
			effectSlots[index] = slot
		end
		return slot
	end

	local nextSwirl = 0
	RunService.Heartbeat:Connect(function()
		-- the icons: good ones in the first row, bad ones below (Minecraft: 25 pixels apart from the right)
		local good, bad, used = 0, 0, 0
		local now = os.clock()
		for _, effect in ipairs(myEffects) do
			if effect.icon == false then
				continue
			end
			local picture = gui("effect_" .. tostring(effect.id))
			if not picture then
				continue
			end
			used += 1
			local slot = effectSlot(used)
			local row, column
			if effect.good ~= false then
				good += 1
				row, column = 0, good
			else
				bad += 1
				row, column = 1, bad
			end
			slot.back.Position = UDim2.fromOffset(250 - 25 * column, 1 + row * 26)
			setPicture(slot.back, gui(if effect.ambient then "effect_background_ambient" else "effect_background"))
			setPicture(slot.icon, picture)
			local seconds = tonumber(effect.dur) or -1
			-- the last 10 seconds: the icon blinks (Minecraft)
			slot.icon.ImageTransparency = if seconds >= 0 and seconds <= 10 then 0.5 - 0.5 * math.cos(now * 6) else 0
		end
		for index = used + 1, #effectSlots do
			effectSlots[index].back.Visible = false
		end
		for index = 1, used do
			effectSlots[index].back.Visible = true
		end
		-- the swirl around every player with an effect (not visible ones: invisible players show none), 4 times a second
		if now >= nextSwirl then
			nextSwirl = now + 0.25
			for _, other in ipairs(Players:GetPlayers()) do
				local character = other.Character
				local root = character and character:FindFirstChild("HumanoidRootPart")
				if not root or not root:IsA("BasePart") then
					continue
				end
				local list = if other == player then myEffects else decodeEffects(other:GetAttribute("McEffects"))
				if #list == 0 or (other == player and (player:GetAttribute("McView") or 1) == 1) then
					continue
				end
				local r, g, b, n = 0, 0, 0, 0
				local invisible = false
				for _, effect in ipairs(list) do
					if effect.id == "invisibility" then
						invisible = true
					end
					if effect.ambient ~= true and type(effect.color) == "number" then
						local colour = effect.color :: number
						r += bit32.rshift(colour, 16) % 256
						g += bit32.rshift(colour, 8) % 256
						b += colour % 256
						n += 1
					end
				end
				if n > 0 and not invisible then
					particleBurst("effect", root.Position - Vector3.new(0, 1.5, 0), Color3.fromRGB(r / n, g / n, b / n))
				end
			end
		end
		-- Minecraft players (NPCs): their swirl colour + invisibility come with their snapshot
		local others: { Model } = {}
		local npcFolder = workspace:FindFirstChild("BridgeRemotePlayers")
		if npcFolder then
			for _, serverFolder in ipairs(npcFolder:GetChildren()) do
				for _, model in ipairs(serverFolder:GetChildren()) do
					if model:IsA("Model") then
						table.insert(others, model)
						local colour = model:GetAttribute("McEffectColor")
						local root = model:FindFirstChild("HumanoidRootPart")
						if type(colour) == "number" and root and root:IsA("BasePart") and model:GetAttribute("McInvisible") ~= true
							and particleRandom:NextNumber() < 0.07 then -- (about 4 times a second)
							particleBurst("effect", root.Position - Vector3.new(0, 1.5, 0),
								Color3.fromRGB(bit32.rshift(colour, 16) % 256, bit32.rshift(colour, 8) % 256, colour % 256))
						end
					end
				end
			end
		end
		for _, other in ipairs(Players:GetPlayers()) do
			if other ~= player and other.Character then
				table.insert(others, other.Character)
			end
		end
		-- invisible players (Minecraft's invisibility): the others do not see them
		for _, character in ipairs(others) do
			do
				local hidden = character:GetAttribute("McInvisible") == true
				if character:GetAttribute("McHiddenHere") ~= hidden then
					character:SetAttribute("McHiddenHere", hidden)
					for _, item in ipairs(character:GetDescendants()) do
						if item:IsA("BasePart") or item:IsA("Decal") or item:IsA("Texture") then
							(item :: any).LocalTransparencyModifier = if hidden then 1 else 0
						end
					end
				end
			end
		end
	end)
end
-- endregion

-- region the item in the hand: at the right arm of everybody (attribute McHeld), in first person bottom right
do -- (its own block: these locals do not count towards the 200 of the script)
	local PIXEL = (assets and assets.scale or 3) / 16
	local HELD_FACES = {
		{ Enum.NormalId.Top, "up" }, { Enum.NormalId.Bottom, "down" }, { Enum.NormalId.Front, "north" },
		{ Enum.NormalId.Back, "south" }, { Enum.NormalId.Right, "east" }, { Enum.NormalId.Left, "west" },
	}
	-- A part that looks like the item: a block item = a small cube with its pictures, everything else = a flat picture
	-- (seen from both sides). size = its width in studs.
	local function heldPart(id: string, size: number): (BasePart?, boolean)
		local item = itemInfo(id)
		if not item then
			return nil, false
		end
		local look = assets and assets.blocks and (assets.blocks[item.look or ""] or assets.blocks[item.block or ""])
		local part = Instance.new("Part")
		part.Name = "McHeldItem"
		part.Anchored = false
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Massless = true
		part.CastShadow = false
		part.Transparency = 1
		if look and look.cube and type(item.icon) ~= "string" then
			part.Size = Vector3.one * size * 0.6
			for _, face in ipairs(HELD_FACES) do
				local content = worldContent(look.faces and look.faces[face[2]], 0)
				if content then
					local texture = Instance.new("Texture")
					texture.Face = face[1]
					texture.StudsPerTileU = part.Size.X
					texture.StudsPerTileV = part.Size.X
					texture.TextureContent = content
					texture.Parent = part
				end
			end
			return part, true
		end
		local content = iconContent(id)
		if not content then
			part:Destroy()
			return nil, false
		end
		part.Size = Vector3.new(0.05, size, size)
		for _, face in ipairs({ Enum.NormalId.Right, Enum.NormalId.Left }) do
			local texture = Instance.new("Texture")
			texture.Face = face
			texture.StudsPerTileU = size
			texture.StudsPerTileV = size
			texture.TextureContent = content
			texture.Parent = part
		end
		return part, false
	end

	local function attachHeld(model: Model)
		local old = model:FindFirstChild("McHeldItem", true)
		if old then
			old:Destroy()
		end
		local id = model:GetAttribute("McHeld")
		local arm = model:FindFirstChild("RightArm")
		if type(id) ~= "string" or not arm or not arm:IsA("BasePart") then
			return
		end
		local part, block = heldPart(id, 10 * PIXEL)
		if not part then
			return
		end
		-- Minecraft (ItemInHandLayer): at the hand, a little forward; tools point forward, blocks sit in the hand
		local weld = Instance.new("Weld")
		weld.Part0 = arm
		weld.Part1 = part
		weld.C0 = if block then CFrame.new(0, -7 * PIXEL, -2 * PIXEL)
			else CFrame.new(0, -6 * PIXEL, -4 * PIXEL) * CFrame.Angles(math.rad(-45), 0, 0)
		weld.Parent = part
		part.Parent = model
	end

	local watchedHeld: { [Model]: boolean } = setmetatable({}, { __mode = "k" }) :: any
	local function watchHeld(model: Model)
		if watchedHeld[model] then
			return
		end
		watchedHeld[model] = true
		model:GetAttributeChangedSignal("McHeld"):Connect(function()
			attachHeld(model)
		end)
		attachHeld(model)
	end

	-- first person: the item bottom right in front of the camera, swinging with the arm (Minecraft's ItemInHandRenderer)
	local firstPersonItem: BasePart? = nil
	local firstPersonId: string? = nil
	RunService.RenderStepped:Connect(function()
		local stack = hotbarStack(selected)
		local id = if stack then stack.id else nil
		local camera = workspace.CurrentCamera
		local show = id ~= nil and camera ~= nil and (player:GetAttribute("McView") or 1) == 1 and not inventoryOpen
			and gameMode() ~= "spectator"
		if id ~= firstPersonId or (show and not firstPersonItem) then
			if firstPersonItem then
				firstPersonItem:Destroy()
				firstPersonItem = nil
			end
			firstPersonId = id
			if id and assets then
				local part = heldPart(id, 0.55 * (assets.scale or 3))
				if part then
					part.Anchored = true
					firstPersonItem = part
				end
			end
		end
		local part = firstPersonItem
		if part and camera then
			part.Parent = if show then camera else nil
			if show then
				local block = assets and assets.scale or 3
				local since = os.clock() - (tonumber(player:GetAttribute("McSwingAt")) or -100)
				local swing = if since < 0.3 then math.sin(since / 0.3 * math.pi) else 0
				if player:GetAttribute("McEating") == "charge" then
					-- a bow drawn: held in the middle in front of the eyes, a little shaking when fully drawn (Minecraft)
					local shake = math.sin(os.clock() * 40) * 0.004
					part.CFrame = camera.CFrame * CFrame.new(0.05 * block, (-0.22 + shake) * block, -0.7 * block)
						* CFrame.Angles(math.rad(-5), math.rad(-80), math.rad(-25))
				elseif player:GetAttribute("McEating") then
					-- eating / drinking: the item at the mouth, bobbing (Minecraft's applyEatTransform)
					local bob = math.abs(math.sin(os.clock() * 16)) * 0.06
					part.CFrame = camera.CFrame * CFrame.new(0.15 * block, (-0.32 + bob) * block, -0.75 * block)
						* CFrame.Angles(math.rad(10), math.rad(-60), math.rad(-20))
				else
					part.CFrame = camera.CFrame * CFrame.new(0.56 * block, (-0.52 - 0.25 * swing) * block, (-0.9 + 0.2 * swing) * block)
						* CFrame.Angles(math.rad(-20 - 60 * swing), math.rad(-35), 0)
				end
			end
		end
		-- third person: everybody's item at the arm (new characters / NPCs get watched); mine not in first person
		for _, other in ipairs(Players:GetPlayers()) do
			if other.Character then
				watchHeld(other.Character)
			end
		end
		local myCharacter = player.Character
		local myHeld = myCharacter and myCharacter:FindFirstChild("McHeldItem")
		if myHeld then
			local hidden = (player:GetAttribute("McView") or 1) == 1
			for _, texture in ipairs(myHeld:GetChildren()) do
				if texture:IsA("Texture") then
					texture.Transparency = if hidden then 1 else 0
				end
			end
		end
		local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
		if npcs then
			for _, serverFolder in ipairs(npcs:GetChildren()) do
				for _, model in ipairs(serverFolder:GetChildren()) do
					if model:IsA("Model") then
						watchHeld(model)
					end
				end
			end
		end
	end)
end
-- endregion

-- region mobs: Minecraft's own models + textures, moved + animated like Minecraft (head, legs, arms)
do -- (its own block: these locals do not count towards the 200 of the script)
	--[[
		The server forwards Minecraft's list (Mobs: {{id, type, x, y, z, bodyYaw, headYaw, pitch, walkPos, walkSpeed, hurt,
		baby, invisible}}) about 10 times a second; each kind's look comes once (MobModel). Drawn only here (anchored
		parts with Minecraft's pictures, moved every frame between two lists), not touchable.
	]]
	local mobsRemoteClient = remotes:WaitForChild("Mobs", 10) :: RemoteEvent?
	-- (riding: the height of the root part's middle above the feet - MinecraftCharacter)
	local ROOT_HEIGHT = (require(ReplicatedStorage:WaitForChild("MinecraftCharacter") :: any) :: any).ROOT_HEIGHT or 2.75
	local mobModelRemote = remotes:WaitForChild("MobModel", 10) :: RemoteFunction?
	local mobFolder = Instance.new("Folder")
	mobFolder.Name = "MinecraftMobs"
	local mobLooks: { [string]: any } = {} -- type -> look | "waiting" | false
	local mobs: { [number]: any } = {} -- id -> {kind, look, parts, from, to, at, model}
	local MOB_PIXEL = (assets and assets.scale or 3) / 16

	local function mobLook(id: number, kind: string)
		if mobLooks[kind] ~= nil or not mobModelRemote then
			return
		end
		mobLooks[kind] = "waiting"
		task.spawn(function()
			local ok, look = pcall(function()
				return (mobModelRemote :: RemoteFunction):InvokeServer(id, kind)
			end)
			if ok and type(look) == "table" and type(look.parts) == "table" then
				if assets then
					for key, texture in pairs(look.textures or {}) do
						assets.textures[key] = texture -- (worldContent makes the pictures)
					end
				end
				mobLooks[kind] = look
			else
				mobLooks[kind] = nil -- (asked again with the next list)
				task.wait(5)
			end
		end)
	end

	-- the parts of one mob: per Minecraft part its boxes (anchored, pictures on all six sides)
	local MOB_FACES = { up = Enum.NormalId.Top, down = Enum.NormalId.Bottom, north = Enum.NormalId.Front,
		south = Enum.NormalId.Back, east = Enum.NormalId.Right, west = Enum.NormalId.Left }
	local function buildMob(look: any, id: number): (Model, { any })
		local model = Instance.new("Model")
		model.Name = "Mob"
		local parts = {}
		for index, spec in ipairs(look.parts) do
			local entry = { spec = spec, boxes = {}, index = index }
			for _, box in ipairs(spec.b or {}) do
				local b = box.b
				local size = Vector3.new(b[4] - b[1], b[5] - b[2], b[6] - b[3]) * MOB_PIXEL
				local part = Instance.new("Part")
				part.Name = spec.n
				part.Anchored = true
				part.CanCollide = false
				part.CanQuery = true -- (aimed at: left click hits it)
				part.CanTouch = false
				part.Transparency = 1
				part:SetAttribute("McMob", id)
				part.Size = Vector3.new(math.max(size.X, 0.02), math.max(size.Y, 0.02), math.max(size.Z, 0.02))
				for direction, key in pairs(box.f or {}) do
					local normal = MOB_FACES[direction]
					-- (Top / Bottom turned like the blocks: /drehen)
					local turn = if normal == Enum.NormalId.Top then tonumber(ReplicatedStorage:GetAttribute("McTopTurn")) or 0
						elseif normal == Enum.NormalId.Bottom then tonumber(ReplicatedStorage:GetAttribute("McBottomTurn")) or 0 else 0
					local content = normal and worldContent(key, turn)
					if content then
						local texture = Instance.new("Texture")
						texture.Face = normal
						local u = if normal == Enum.NormalId.Top or normal == Enum.NormalId.Bottom then part.Size.X
							elseif normal == Enum.NormalId.Left or normal == Enum.NormalId.Right then part.Size.Z else part.Size.X
						local v = if normal == Enum.NormalId.Top or normal == Enum.NormalId.Bottom then part.Size.Z else part.Size.Y
						texture.StudsPerTileU = u
						texture.StudsPerTileV = v
						texture.TextureContent = content
						pcall(function()
							texture.ResampleMode = Enum.ResamplerMode.Pixelated
						end)
						texture.Parent = part
					end
				end
				part.Parent = model
				table.insert(entry.boxes, { part = part,
					offset = CFrame.new(Vector3.new(b[1] + b[4], b[2] + b[5], b[3] + b[6]) / 2 * MOB_PIXEL) })
			end
			parts[index] = entry
		end
		return model, parts
	end

	-- Minecraft's walking animation by part names (QuadrupedModel / HumanoidModel), head turned + tilted
	local ARMS_FORWARD = { ["minecraft:zombie"] = true, ["minecraft:husk"] = true, ["minecraft:drowned"] = true,
		["minecraft:zombie_villager"] = true, ["minecraft:zombified_piglin"] = true, ["minecraft:skeleton"] = false }
	local function animate(name: string, pos: number, speed: number, headYaw: number, pitch: number, kind: string?): (number, number)
		local swing = pos * 0.6662
		if kind and ARMS_FORWARD[kind] and (name == "right_arm" or name == "left_arm") then
			-- Minecraft's zombies hold their arms out in front (AnimationUtils.animateZombieArms)
			return -math.pi / 2 + math.cos(os.clock() * 1.8) * 0.05, 0
		end
		if name == "head" then
			return math.rad(pitch), math.rad(headYaw)
		elseif name == "right_hind_leg" or name == "left_front_leg" or name == "right_leg" then
			return math.cos(swing) * 1.4 * speed, 0
		elseif name == "left_hind_leg" or name == "right_front_leg" or name == "left_leg" then
			return math.cos(swing + math.pi) * 1.4 * speed, 0
		elseif name == "right_arm" then
			return math.cos(swing + math.pi) * speed, 0
		elseif name == "left_arm" then
			return math.cos(swing) * speed, 0
		end
		return 0, 0
	end

	-- region things that are no mobs (in the same list: [id, type, x, y, z (middle), yaw, pitch, size x, y, z, extra,
	-- facing]): falling blocks + lit TNT (their block), experience orbs, arrows / tridents, thrown things (snowballs,
	-- potions, pearls, fireballs: their item), item frames (the item on the frame), paintings (Minecraft's picture)
	local things = {}
	local thingFolder = Instance.new("Folder")
	thingFolder.Name = "MinecraftThings"

	local function thingPart(model: Instance, size: Vector3, color: Color3?): Part
		local part = Instance.new("Part")
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.CastShadow = false
		part.Size = Vector3.new(math.max(size.X, 0.05), math.max(size.Y, 0.05), math.max(size.Z, 0.05))
		part.Color = color or Color3.new(1, 1, 1)
		part.Transparency = if color then 0 else 1
		part.Parent = model
		return part
	end

	local function buildThing(thing: any)
		if thing.model then
			thing.model:Destroy()
		end
		local scale = assets and assets.scale or 3
		local data = thing.to
		local kind = thing.kind
		local extra = tostring(data[11] or "")
		local size = Vector3.new(tonumber(data[8]) or 0.5, tonumber(data[9]) or 0.5, tonumber(data[10]) or 0.5) * scale
		local model = Instance.new("Model")
		model.Name = kind
		local pieces = {} -- {part, offset from the middle}
		local function addPieces()
			for _, item in ipairs(model:GetChildren()) do
				if item:IsA("BasePart") then
					table.insert(pieces, { part = item, offset = item.CFrame })
				end
			end
		end
		if kind == "minecraft:falling_block" or kind == "minecraft:tnt" then
			local name = string.match(extra, "^[^|]+") or extra
			local look = assets and assets.blocks and assets.blocks[name]
			if look and look.cube and type(look.faces) == "table" then
				itemPiece(model, Vector3.one * scale * 0.98, CFrame.new(), look.faces)
			elseif look and look.model and type(look.parts) == "table" then
				local unit = scale / 16
				for _, piece in ipairs(look.parts) do
					if type(piece.b) == "table" then
						local b = piece.b
						itemPiece(model, Vector3.new(b[4] - b[1], b[5] - b[2], b[6] - b[3]) * unit,
							CFrame.new(Vector3.new((b[1] + b[4]) / 2 - 8, (b[2] + b[5]) / 2 - 8, (b[3] + b[6]) / 2 - 8) * unit), piece.f or {})
					end
				end
			else
				thingPart(model, Vector3.one * scale * 0.98, Color3.fromRGB(150, 150, 150))
			end
		elseif kind == "minecraft:ender_dragon" then
			-- (Minecraft draws the dragon with code, no model to take): a dark body, neck, head, wings, purple eyes
			local body = thingPart(model, Vector3.new(4, 3, 7) * scale, Color3.fromRGB(25, 25, 30))
			body.CFrame = CFrame.new(0, 0, 0)
			local neck = thingPart(model, Vector3.new(1.5, 1.5, 4) * scale, Color3.fromRGB(30, 30, 36))
			neck.CFrame = CFrame.new(0, 0.6 * scale, -5 * scale)
			local head = thingPart(model, Vector3.new(2, 1.6, 2.6) * scale, Color3.fromRGB(35, 35, 40))
			head.CFrame = CFrame.new(0, 0.8 * scale, -8 * scale)
			for side = -1, 1, 2 do
				local eye = thingPart(model, Vector3.new(0.4, 0.3, 0.1) * scale, Color3.fromRGB(220, 80, 255))
				eye.Material = Enum.Material.Neon
				eye.CFrame = CFrame.new(side * 0.6 * scale, 1.1 * scale, -9.32 * scale)
				local wing = thingPart(model, Vector3.new(8, 0.2, 5) * scale, Color3.fromRGB(40, 38, 48))
				wing.CFrame = CFrame.new(side * 6 * scale, 1 * scale, 0)
			end
			local tail = thingPart(model, Vector3.new(1, 1, 8) * scale, Color3.fromRGB(28, 28, 33))
			tail.CFrame = CFrame.new(0, 0, 7.5 * scale)
			for _, item in ipairs(model:GetChildren()) do
				item:SetAttribute("McMob", data[1]) -- (it can be hit)
				if item:IsA("BasePart") then
					item.CanQuery = true
				end
			end
		elseif string.find(kind, "minecart", 1, true) or string.find(kind, "boat", 1, true) or string.find(kind, "raft", 1, true) then
			-- minecarts + boats (Minecraft's models are code): their box, a minecart grey iron, a boat its wood; a chest /
			-- furnace / TNT / hopper on it as a small block. They can be hit (break) and right-clicked (open a chest cart)
			local cart = string.find(kind, "minecart", 1, true) ~= nil
			local bottom = thingPart(model, Vector3.new(size.X, size.Y * (if cart then 0.75 else 0.5), size.Z),
				if cart then Color3.fromRGB(110, 110, 115) else Color3.fromRGB(140, 105, 60))
			bottom.Material = if cart then Enum.Material.Metal else Enum.Material.WoodPlanks
			bottom.CFrame = CFrame.new(0, -size.Y * (if cart then 0.125 else 0.25), 0)
			local cargo = string.match(kind, "^minecraft:(%w+)_minecart$") or (if string.find(kind, "chest", 1, true) then "chest" else nil)
			local block = if cargo == "chest" then "minecraft:chest" elseif cargo == "furnace" then "minecraft:furnace"
				elseif cargo == "tnt" then "minecraft:tnt" elseif cargo == "hopper" then "minecraft:hopper"
				elseif cargo == "spawner" then "minecraft:spawner" elseif cargo == "command_block" then "minecraft:command_block" else nil
			local look = block and assets and assets.blocks and assets.blocks[block]
			if look and look.cube and type(look.faces) == "table" then
				itemPiece(model, Vector3.one * scale * 0.75, CFrame.new(0, size.Y * 0.3, 0), look.faces)
			elseif block then
				local box = thingPart(model, Vector3.one * scale * 0.75, Color3.fromRGB(150, 110, 50))
				box.CFrame = CFrame.new(0, size.Y * 0.3, 0)
			end
			for _, item in ipairs(model:GetChildren()) do
				if item:IsA("BasePart") then
					item:SetAttribute("McMob", data[1])
					item.CanQuery = true
				end
			end
		elseif kind == "minecraft:fishing_bobber" then
		-- the bobber: red on top, white below
		local top = thingPart(model, Vector3.new(0.25, 0.15, 0.25) * scale, Color3.fromRGB(200, 30, 30))
		top.CFrame = CFrame.new(0, 0.07 * scale, 0)
		local bottom = thingPart(model, Vector3.new(0.25, 0.12, 0.25) * scale, Color3.fromRGB(240, 240, 240))
		bottom.CFrame = CFrame.new(0, -0.07 * scale, 0)
	elseif kind == "minecraft:lightning_bolt" then
			-- a lightning bolt: a zigzag of light from high up down to where it strikes (Minecraft's LightningBoltRenderer)
			local random = Random.new(data[1])
			local x, z = 0, 0
			for i = 0, 7 do
				local nx, nz = x + random:NextNumber(-1.5, 1.5), z + random:NextNumber(-1.5, 1.5)
				local from = Vector3.new(x, i * 6, z) * scale
				local to = Vector3.new(nx, (i + 1) * 6, nz) * scale
				local piece = thingPart(model, Vector3.new(0.25 * scale, 0.25 * scale, (to - from).Magnitude), Color3.fromRGB(200, 220, 255))
				piece.Material = Enum.Material.Neon
				piece.CFrame = CFrame.lookAt((from + to) / 2, to)
				x, z = nx, nz
			end
		elseif kind == "minecraft:end_crystal" then
			local core = thingPart(model, Vector3.one * scale * 0.5, Color3.fromRGB(255, 120, 230))
			core.Material = Enum.Material.Neon
			core.Name = "Core"
			local glass = thingPart(model, Vector3.one * scale * 0.85, Color3.fromRGB(230, 200, 255))
			glass.Transparency = 0.7
			glass.Material = Enum.Material.Glass
			glass.Name = "Glass"
			if extra == "bottom" then
				local base = thingPart(model, Vector3.new(1, 0.5, 1) * scale, Color3.fromRGB(70, 70, 70))
				base.CFrame = CFrame.new(0, -0.75 * scale, 0)
			end
			for _, item in ipairs(model:GetChildren()) do
				item:SetAttribute("McMob", data[1]) -- (a hit makes it explode, like Minecraft)
				if item:IsA("BasePart") then
					item.CanQuery = true
				end
			end
		elseif kind == "minecraft:experience_orb" then
			local value = tonumber(extra) or 1
			local orb = thingPart(model, Vector3.one * scale * (0.18 + math.min(0.22, value / 120)), Color3.fromRGB(180, 255, 60))
			orb.Shape = Enum.PartType.Ball
			orb.Material = Enum.Material.Neon
		elseif kind == "minecraft:item_frame" or kind == "minecraft:glow_item_frame" or kind == "minecraft:painting" then
			local facing = tostring(data[12] or "south")
			if kind == "minecraft:painting" then
				local look = mobLooks[kind .. "|" .. extra]
				if type(look) == "table" and type(look.picture) == "string" then
					itemPiece(model, size, CFrame.new(), { [facing] = look.picture })
				else
					mobLook(data[1], kind .. "|" .. extra)
					thingPart(model, size, Color3.fromRGB(120, 85, 50))
					thing.waitPicture = true
				end
			else
				thingPart(model, size, if kind == "minecraft:glow_item_frame" then Color3.fromRGB(150, 140, 90) else Color3.fromRGB(125, 90, 55))
				local item = extra ~= "" and itemInfo(extra)
				if item and type(item.icon) == "string" then
					-- the item lies on the frame, a little in front of it
					local normal = Vector3.FromNormalId(FACE_NORMALS[facing] or Enum.NormalId.Back)
					local flat = Vector3.new(if normal.X ~= 0 then 0.02 else size.X * 0.8, if normal.Y ~= 0 then 0.02 else size.Y * 0.8,
						if normal.Z ~= 0 then 0.02 else size.Z * 0.8)
					itemPiece(model, flat, CFrame.new(normal * (math.max(size.X, size.Y, size.Z) > 0 and 0.06 or 0) * scale),
						{ [facing] = item.icon })
				end
			end
		elseif kind == "minecraft:arrow" or kind == "minecraft:spectral_arrow" or kind == "minecraft:trident" then
			local trident = kind == "minecraft:trident"
			thingPart(model, Vector3.new(0.06, 0.06, if trident then 0.9 else 0.5) * scale,
				if trident then Color3.fromRGB(90, 160, 150) elseif kind == "minecraft:spectral_arrow" then Color3.fromRGB(230, 200, 80)
					else Color3.fromRGB(110, 80, 50))
		else
			-- thrown (snowball, egg, potion, ender pearl, fireball ...): its picture, always facing the camera
			local anchor = thingPart(model, Vector3.one * 0.1)
			local billboard = Instance.new("BillboardGui")
			billboard.Size = UDim2.fromScale(scale * 0.5, scale * 0.5)
			billboard.LightInfluence = 0
			billboard.Adornee = anchor
			local label = Instance.new("ImageLabel")
			label.BackgroundTransparency = 1
			label.Size = UDim2.fromScale(1, 1)
			label.ResampleMode = Enum.ResamplerMode.Pixelated
			label.ImageContent = iconContent(extra) or Content.none
			label.Parent = billboard
			billboard.Parent = anchor
		end
		if kind == "minecraft:item_frame" or kind == "minecraft:glow_item_frame" or kind == "minecraft:painting" then
			-- (left click: Minecraft breaks it / takes the item out, right click: puts an item in / turns it)
			for _, item in ipairs(model:GetChildren()) do
				if item:IsA("BasePart") then
					item:SetAttribute("McMob", data[1])
					item.CanQuery = true
				end
			end
		end
		addPieces()
		thing.model = model
		thing.pieces = pieces
		thing.built = extra
		model.Parent = thingFolder
	end

	if mobsRemoteClient then
		(mobsRemoteClient :: RemoteEvent).OnClientEvent:Connect(function(list)
			if type(list) ~= "table" or not assets then
				return
			end
			local now = os.clock()
			local seen = {}
			local thingsSeen = {}
			for _, data in ipairs(list) do
				local id = data[1]
				if type(id) ~= "number" or type(data[2]) ~= "string" then
					continue
				end
				if type(data[11]) == "string" then
					-- a thing (no mob)
					thingsSeen[id] = true
					local thing = things[id]
					if not thing then
						thing = { kind = data[2] }
						things[id] = thing
					end
					thing.from = thing.to or data
					thing.to = data
					thing.at = now
					continue
				end
				seen[id] = true
				local mob = mobs[id]
				if not mob then
					mob = { kind = data[2] }
					mobs[id] = mob
				end
				mob.from = mob.to or data
				mob.to = data
				mob.at = now
				mobLook(id, data[2])
			end
			for id, mob in pairs(mobs) do
				if not seen[id] then
					if mob.model then
						mob.model:Destroy()
					end
					mobs[id] = nil
				end
			end
			for id, thing in pairs(things) do
				if not thingsSeen[id] then
					if thing.model then
						thing.model:Destroy()
					end
					things[id] = nil
				end
			end
		end)
	end

	RunService.RenderStepped:Connect(function()
		if not next(things) or not assets or not assets.minY then
			return
		end
		if not thingFolder.Parent then
			thingFolder.Parent = workspace
		end
		local scale = assets.scale or 3
		local now = os.clock()
		local moveParts, moveFrames = {}, {}
		for _, thing in pairs(things) do
			local a, b = thing.from, thing.to
			local extra = tostring(b[11] or "")
			if not thing.model or thing.built ~= extra
				or (thing.waitPicture and type(mobLooks[thing.kind .. "|" .. extra]) == "table") then
				thing.waitPicture = nil
				buildThing(thing)
			end
			local t = math.clamp((now - thing.at) / 0.1, 0, 1)
			local function mix(i: number): number
				return (tonumber(a[i]) or 0) + ((tonumber(b[i]) or 0) - (tonumber(a[i]) or 0)) * t
			end
			local middle = Vector3.new(mix(3) * scale, (mix(4) - assets.minY) * scale, mix(5) * scale)
			local frame = CFrame.new(middle)
			local kind = thing.kind
			if kind == "minecraft:arrow" or kind == "minecraft:spectral_arrow" or kind == "minecraft:trident" then
				-- Minecraft's arrow: yaw = atan2(dx, dz), pitch = atan2(dy, horizontal)
				local yaw, pitch = math.rad(tonumber(b[6]) or 0), math.rad(tonumber(b[7]) or 0)
				local direction = Vector3.new(math.sin(yaw) * math.cos(pitch), math.sin(pitch), math.cos(yaw) * math.cos(pitch))
				frame = CFrame.lookAt(middle, middle + direction)
			elseif kind == "minecraft:tnt" then
				-- lit TNT flashes white (Minecraft: every 5 ticks) and swells before it goes off
				local fuse = tonumber(string.match(extra, "|(%-?%d+)$")) or 80
				local white = math.floor(fuse / 5) % 2 == 0
				for _, piece in ipairs(thing.pieces) do
					for _, texture in ipairs(piece.part:GetChildren()) do
						if texture:IsA("Texture") then
							texture.Transparency = if white then 0.55 else 0
						end
					end
					piece.part.Transparency = if white then 0 else 1
					piece.part.Color = Color3.new(1, 1, 1)
				end
			elseif kind == "minecraft:experience_orb" then
				frame = frame * CFrame.new(0, math.sin(now * 6 + (b[1] % 7)) * 0.08 * scale, 0)
			elseif string.find(kind, "minecart", 1, true) or string.find(kind, "boat", 1, true) or string.find(kind, "raft", 1, true) then
				frame = frame * CFrame.Angles(0, math.rad(-(tonumber(b[6]) or 0)), 0)
				if b[1] == player:GetAttribute("McRideMob") then
					local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart") :: BasePart?
					local half = (tonumber(b[9]) or 0) * scale / 2
					if player:GetAttribute("McRideMode") == "cart" then
						-- his minecart (Minecraft moves it): he sits in it (MinecraftPlayer holds him there)
						player:SetAttribute("McCartAt", CFrame.new(middle - Vector3.new(0, half, 0)))
					elseif root then
						-- his boat (he steers it): right under him, now - not where Minecraft had it a moment ago
						local look = root.CFrame.LookVector
						local feet = root.Position - Vector3.new(0, ROOT_HEIGHT, 0)
						-- (the same turn as above: -Minecraft's yaw, his yaw = atan2(-look.X, look.Z))
						frame = CFrame.new(feet + Vector3.new(0, half, 0)) * CFrame.Angles(0, math.atan2(look.X, look.Z), 0)
					end
				end
			elseif kind == "minecraft:ender_dragon" then
				-- Minecraft's dragon yaw: 180 - yaw like the mobs, its head at -z of the model
				frame = frame * CFrame.Angles(0, math.rad(180 - (tonumber(b[6]) or 0)), 0)
			elseif kind == "minecraft:end_crystal" then
				-- the crystal turns and bobs (the base stays)
				local spin = CFrame.new(0, (0.35 + math.sin(now * 2) * 0.15) * scale, 0) * CFrame.Angles(now * 1.5, now * 2, 0)
				for _, piece in ipairs(thing.pieces) do
					table.insert(moveParts, piece.part)
					table.insert(moveFrames, if piece.part.Name == "Core" or piece.part.Name == "Glass" then frame * spin
						else frame * piece.offset)
				end
				continue
			end
			for _, piece in ipairs(thing.pieces) do
				table.insert(moveParts, piece.part)
				table.insert(moveFrames, frame * piece.offset)
			end
		end
		if #moveParts > 0 then
			workspace:BulkMoveTo(moveParts, moveFrames, Enum.BulkMoveMode.FireCFrameChanged)
		end
	end)
	-- endregion

	local function lerpAngle(a: number, b: number, t: number): number
		local difference = ((b - a + 180) % 360) - 180
		return a + difference * t
	end

	RunService.RenderStepped:Connect(function()
		if not next(mobs) or not assets or not assets.minY then
			return
		end
		if not mobFolder.Parent then
			mobFolder.Parent = workspace
		end
		local scale = assets.scale or 3
		local now = os.clock()
		local moveParts, moveFrames = {}, {}
		local ridden = player:GetAttribute("McRideMob")
		local riderRoot = if ridden and player.Character then player.Character:FindFirstChild("HumanoidRootPart") :: BasePart? else nil
		for id, mob in pairs(mobs) do
			local look = mobLooks[mob.kind]
			if type(look) ~= "table" then
				continue
			end
			if not mob.model then
				mob.model, mob.parts = buildMob(look, id)
				mob.model.Parent = mobFolder
			end
			-- a name tag (Minecraft: its custom name above it)
			local tag = if type(mob.to[14]) == "string" and mob.to[14] ~= "" then mob.to[14] else nil
			if mob.tag ~= tag then
				mob.tag = tag
				local old = mob.model:FindFirstChild("McNameTag", true)
				if old then
					old:Destroy()
				end
				local anchor = nil
				for _, entry in ipairs(mob.parts) do
					for _, box in ipairs(entry.boxes) do
						if not anchor or box.part.Size.Magnitude > anchor.Size.Magnitude then
							anchor = box.part
						end
					end
				end
				if tag and anchor then
					local billboard = Instance.new("BillboardGui")
					billboard.Name = "McNameTag"
					billboard.Size = UDim2.fromOffset(200, 20)
					billboard.StudsOffsetWorldSpace = Vector3.new(0, (assets.scale or 3) * 1.1, 0)
					billboard.LightInfluence = 0
					billboard.MaxDistance = 64
					billboard.AlwaysOnTop = false
					local label = Instance.new("TextLabel")
					label.BackgroundColor3 = Color3.new(0, 0, 0)
					label.BackgroundTransparency = 0.75
					label.AutomaticSize = Enum.AutomaticSize.X
					label.Size = UDim2.fromOffset(0, 18)
					label.AnchorPoint = Vector2.new(0.5, 0)
					label.Position = UDim2.fromScale(0.5, 0)
					label.Font = Enum.Font.Arcade
					label.TextSize = 16
					label.TextColor3 = Color3.new(1, 1, 1)
					label.Text = " " .. tag .. " "
					label.Parent = billboard
					billboard.Parent = anchor
				end
			end
			local a, b = mob.from, mob.to
			local t = math.clamp((now - mob.at) / 0.1, 0, 1) -- (a list every 2 ticks: 0.1 s from the last to the newest)
			local function mix(i: number): number
				return (tonumber(a[i]) or 0) + ((tonumber(b[i]) or 0) - (tonumber(a[i]) or 0)) * t
			end
			local bodyYaw = lerpAngle(tonumber(a[6]) or 0, tonumber(b[6]) or 0, t)
			local headYaw = lerpAngle(tonumber(a[7]) or 0, tonumber(b[7]) or 0, t)
			local pitch = mix(8)
			local walkPos, walkSpeed = mix(9), mix(10)
			local baby = b[12] == true
			local hidden = b[13] == true
			local feet = Vector3.new(mix(3) * scale, (mix(4) - assets.minY) * scale, mix(5) * scale)
			if id == ridden and riderRoot then
				-- the horse / pig he rides (he steers it): right under him, turned like him - not a moment behind
				local look = riderRoot.CFrame.LookVector
				feet = riderRoot.Position - Vector3.new(0, ROOT_HEIGHT, 0)
				bodyYaw = math.deg(math.atan2(-look.X, look.Z))
				headYaw = bodyYaw
			end
			-- Minecraft: rotate (180 - body yaw), the model hangs 1.5 blocks above the feet (babies half as big)
			local size = if baby then 0.5 else 1
			local origin = CFrame.new(feet) * CFrame.Angles(0, math.rad(180 - bodyYaw), 0) * CFrame.new(0, 24 * MOB_PIXEL * size, 0)
			local frames = {}
			for index, entry in ipairs(mob.parts) do
				local spec = entry.spec
				local parent = if spec.p and spec.p >= 0 then frames[spec.p + 1] else origin
				local o, r = spec.o or { 0, 0, 0 }, spec.r or { 0, 0, 0 }
				local ax, ay = animate(spec.n, walkPos, walkSpeed, headYaw - bodyYaw, pitch, mob.kind)
				-- Minecraft's rotation (z, y, x order) turned into Roblox axes: x and y flip their sign
				local frame = (parent or origin) * CFrame.new(Vector3.new(o[1], o[2], o[3]) * MOB_PIXEL * size)
					* CFrame.Angles(0, 0, r[3]) * CFrame.Angles(0, -(r[2] + ay), 0) * CFrame.Angles(-(r[1] + ax), 0, 0)
				frames[index] = frame
				for _, box in ipairs(entry.boxes) do
					table.insert(moveParts, box.part)
					table.insert(moveFrames, frame * box.offset)
					if baby and not box.part:GetAttribute("McBaby") then
						box.part:SetAttribute("McBaby", true)
						box.part.Size *= 0.5
						box.offset = CFrame.new(box.offset.Position * 0.5)
					end
				end
			end
			-- hurt = red (Minecraft's red overlay), invisible = not drawn - only when it changes
			local look2 = (if hidden then "h" else "v") .. (if b[11] == true then "r" else "n")
			if mob.shown ~= look2 then
				mob.shown = look2
				for _, entry in ipairs(mob.parts) do
					for _, box in ipairs(entry.boxes) do
						for _, texture in ipairs(box.part:GetChildren()) do
							if texture:IsA("Texture") then
								texture.Transparency = if hidden then 1 else 0
								texture.Color3 = if b[11] == true then Color3.fromRGB(255, 120, 120) else Color3.new(1, 1, 1)
							end
						end
					end
				end
			end
		end
		if #moveParts > 0 then
			workspace:BulkMoveTo(moveParts, moveFrames, Enum.BulkMoveMode.FireCFrameChanged)
		end
	end)
end
-- endregion

-- region lights: only the nearest block lights shine (and only the nearest few cast shadows)
--[[
	Minecraft's light is free, Roblox pays for every PointLight on every frame - with shadows (Future lighting) a lot.
	A Nether full of lava, a glowstone ceiling or a lit village made dozens of shadow-casting lights and the frame rate
	broke down. Every 0.3 s: the McLight lights of the world sorted by distance to the camera, the nearest MAX on (within
	their reach + a bit), shadows only for the nearest SHADOWS. Only on this client (the server's lights stay as they are).
	How many: Roblox's graphics quality (Esc > Settings), like Minecraft's video settings.
]]
do -- (its own block: these locals do not count towards the 200 of the script)
	local lights: { [PointLight]: boolean } = {}
	local tracked = 0
	local function track(item: Instance)
		if item:IsA("PointLight") and item.Name == "McLight" and not lights[item] then
			lights[item] = true
			tracked += 1
		end
	end
	local function untrack(item: Instance)
		if lights[item :: any] then
			lights[item :: any] = nil
			tracked -= 1
		end
	end
	local function budget(): (number, number)
		local level = 0
		pcall(function()
			level = UserSettings():GetService("UserGameSettings").SavedQualityLevel.Value
		end)
		if level == 0 then
			return 24, 4 -- (automatic)
		elseif level <= 3 then
			return 8, 1
		elseif level <= 6 then
			return 16, 3
		end
		return 32, 6
	end
	task.spawn(function()
		local world = workspace:WaitForChild("MinecraftWorld", 60)
		if not world then
			return
		end
		world.DescendantAdded:Connect(track)
		world.DescendantRemoving:Connect(untrack)
		for _, item in ipairs(world:GetDescendants()) do
			track(item)
		end
		local list = {}
		while true do
			task.wait(0.3)
			local camera = workspace.CurrentCamera
			if not camera or tracked == 0 then
				continue
			end
			local eye = camera.CFrame.Position
			local most, shadows = budget()
			table.clear(list)
			for light in pairs(lights) do
				local part = light.Parent
				if part and part:IsA("BasePart") then
					table.insert(list, { light, (part.Position - eye).Magnitude - light.Range })
				end
			end
			table.sort(list, function(a, b)
				return a[2] < b[2]
			end)
			local on, shadowed = 0, 0
			for index, item in ipairs(list) do
				local light: PointLight = item[1]
				local enabled = index <= most and item[2] < 24 -- (its reach + 8 blocks from the eye)
				local shadow = enabled and index <= shadows
				if light.Enabled ~= enabled then
					light.Enabled = enabled
				end
				if light.Shadows ~= shadow then
					light.Shadows = shadow
				end
				on += if enabled then 1 else 0
				shadowed += if shadow then 1 else 0
			end
			player:SetAttribute("McLightsInfo", string.format("%d/%d an, %d Schatten", on, tracked, shadowed)) -- (F3)
		end
	end)
end
-- endregion

-- region sounds: what Minecraft plays near him (remote Sounds, from the topic mcworld.sounds) + the footsteps of
-- everybody (Minecraft's clients make those themselves: one step per 1.67 blocks walked, the block's sound group)
do -- (its own block: these locals do not count towards the 200 of the script)
	local soundsOk, Sounds = pcall(function()
		return require(ReplicatedStorage:WaitForChild("MinecraftSounds", 10) :: any) :: any
	end)
	local soundsRemoteClient = remotes:WaitForChild("Sounds", 10) :: RemoteEvent?
	if soundsOk and Sounds and soundsRemoteClient then
		(soundsRemoteClient :: RemoteEvent).OnClientEvent:Connect(function(list)
			if type(list) ~= "table" or not assets or not assets.minY or not Sounds.available() then
				return
			end
			local scale = assets.scale or 3
			for _, entry in ipairs(list) do
				if type(entry) == "table" and type(entry[1]) == "string" then
					Sounds.play(entry[1], Vector3.new((tonumber(entry[2]) or 0) * scale, ((tonumber(entry[3]) or 0) - assets.minY) * scale,
						(tonumber(entry[4]) or 0) * scale), tonumber(entry[5]), tonumber(entry[6]))
				end
			end
		end)
		local stepParams = RaycastParams.new()
		stepParams.FilterType = Enum.RaycastFilterType.Include
		local walked = setmetatable({}, { __mode = "k" }) -- model -> {last, dist, nextStep}
		local function stepsOf(model: Model, scale: number)
			local root = model:FindFirstChild("HumanoidRootPart") :: BasePart?
			if not root or model:GetAttribute("McPosedSeat") ~= nil then
				return -- (riding: no steps)
			end
			local state = walked[model]
			if not state then
				state = { last = root.Position, dist = 0, nextStep = 1 }
				walked[model] = state
			end
			local delta = root.Position - state.last
			state.last = root.Position
			local flat = Vector3.new(delta.X, 0, delta.Z).Magnitude / scale
			if flat > 2 or math.abs(delta.Y) > 0.25 * scale then
				return -- (a teleport, a jump, falling: no steps)
			end
			state.dist += flat * 0.6 -- (Minecraft: moveDist += horizontal distance x 0.6, a step at every whole number)
			if state.dist <= state.nextStep then
				return
			end
			state.nextStep = state.dist + 1
			local world = workspace:FindFirstChild("MinecraftWorld")
			if not world then
				return
			end
			stepParams.FilterDescendantsInstances = { world }
			local bottom = root.Position - Vector3.new(0, root.Size.Y / 2, 0)
			local hit = workspace:Raycast(bottom + Vector3.new(0, 0.2, 0), Vector3.new(0, -0.35 * scale - 0.2, 0), stepParams)
			if not hit then
				return
			end
			local name = hit.Instance.Name
			if not string.find(name, ":", 1, true) and hit.Instance.Parent then
				name = hit.Instance.Parent.Name
			end
			local event = Sounds.stepSound(name)
			if event then
				Sounds.play(event, hit.Position, 0.15, 1) -- (Minecraft: a step at 0.15 of the group's volume)
			end
		end
		RunService.Heartbeat:Connect(function()
			if not assets or not Sounds.available() then
				return
			end
			local scale = assets.scale or 3
			for _, other in ipairs(Players:GetPlayers()) do
				if other.Character then
					stepsOf(other.Character, scale)
				end
			end
			local npcs = workspace:FindFirstChild("BridgeRemotePlayers")
			if npcs then
				for _, folder in ipairs(npcs:GetChildren()) do
					for _, model in ipairs(folder:GetChildren()) do
						if model:IsA("Model") then
							stepsOf(model, scale)
						end
					end
				end
			end
		end)
		-- his own hurt sound (Minecraft: the hurt player hears himself)
		local hurtSoundRemote = remotes:FindFirstChild("Hurt") :: RemoteEvent?
		if hurtSoundRemote then
			hurtSoundRemote.OnClientEvent:Connect(function()
				local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart") :: BasePart?
				if root then
					Sounds.play("entity.player.hurt", root.Position, 1, 0.9 + math.random() * 0.2)
				end
			end)
		end
	end
end
-- endregion

-- region crosshair + attack indicator (Minecraft: the charge of the next hit under the crosshair)
do -- (its own block: these locals do not count towards the 200 of the script)
	local crosshair = image(screen, "Crosshair", 0, 0, 15, 15, 5)
	crosshair.AnchorPoint = Vector2.new(0.5, 0.5)
	crosshair.Position = UDim2.fromScale(0.5, 0.5)
	scaled(crosshair)
	local indicator = image(screen, "AttackIndicator", 0, 0, 16, 4, 5)
	indicator.AnchorPoint = Vector2.new(0.5, 0)
	scaled(indicator)
	local indicatorClip = Instance.new("Frame") -- shows the left part of the full bar (charge x 17 pixels)
	indicatorClip.Name = "Clip"
	indicatorClip.BackgroundTransparency = 1
	indicatorClip.ClipsDescendants = true
	indicatorClip.Size = UDim2.fromOffset(0, 4)
	indicatorClip.ZIndex = 6
	indicatorClip.Parent = indicator
	local indicatorFill = image(indicatorClip, "Progress", 0, 0, 16, 4, 6)
	RunService.RenderStepped:Connect(function()
		local playing = UserInputService.MouseBehavior == Enum.MouseBehavior.LockCenter and not inventoryOpen
		local firstPerson = (player:GetAttribute("McView") or 1) == 1
		local cross = gui("crosshair")
		crosshair.Visible = playing and firstPerson and cross ~= nil and gameMode() ~= "spectator"
		if cross and crosshair.ImageContent ~= cross then
			setPicture(crosshair, cross)
		end
		-- charge: (ticks since the last swing + 0.5) / (20 / attack speed of the item in the hand), shown while < 1
		local stack = hotbarStack(selected)
		local info = stack and itemInfo(stack.id)
		local speed = if info and tonumber(info.speed) then tonumber(info.speed) :: number else 4
		local since = os.clock() - (tonumber(player:GetAttribute("McSwingAt")) or -100)
		local charge = math.clamp((since * 20 + 0.5) / (20 / math.max(0.1, speed)), 0, 1)
		local background, progress = gui("crosshair_attack_indicator_background"), gui("crosshair_attack_indicator_progress")
		indicator.Visible = crosshair.Visible and charge < 1 and background ~= nil and progress ~= nil
		if indicator.Visible then
			local scale = guiScale()
			indicator.Position = UDim2.new(0.5, 0, 0.5, 9 * scale)
			setPicture(indicator, background)
			setPicture(indicatorFill, progress)
			indicatorClip.Size = UDim2.fromOffset(math.min(16, math.floor(charge * 17)), 4)
		end
	end)
end
-- endregion

-- "/drehen test": a board in front of him to find TopTurn / BottomTurn without comparing with Minecraft. Each block
-- has an arrow on its top (bottom) - drawn pointing to the top of the picture, then turned by 0 / 90 / 180 / 270 like
-- the world's pictures are turned. Minecraft's pictures: on an up face the top of the picture is north, on a down face
-- south (Models.FRAME). So: the top arrow that points north (to the red N pole) = TopTurn, the bottom arrow that points
-- south = BottomTurn. Only on this client; the same command again takes it away.
do -- (its own block: these locals do not count towards the 200 of the script)
	local calibrateRemote = remotes:WaitForChild("Chat", 10) :: RemoteEvent?
	local board: Model? = nil
	local function arrowPicture(): any
		local size = 16
		local pixels = buffer.create(size * size * 4)
		for y = 0, size - 1 do
			for x = 0, size - 1 do
				-- white ground, a black arrow pointing up (head: rows 1-6, shaft: rows 7-14), a red dot on its right side
				local inHead = y >= 1 and y <= 6 and math.abs(x - 7.5) <= (y - 0.5)
				local inShaft = y >= 7 and y <= 14 and x >= 6 and x <= 9
				local dot = y >= 10 and y <= 12 and x >= 12 and x <= 14
				local r, g, b = 240, 240, 240
				if inHead or inShaft then
					r, g, b = 20, 20, 20
				elseif dot then
					r, g, b = 220, 30, 30
				end
				buffer.writeu32(pixels, (y * size + x) * 4, bit32.bor(r, bit32.lshift(g, 8), bit32.lshift(b, 16), bit32.lshift(255, 24)))
			end
		end
		return { w = size, h = size, pixels = pixels }
	end
	local function label(part: BasePart, text: string, color: Color3)
		local billboard = Instance.new("BillboardGui")
		billboard.Size = UDim2.fromOffset(120, 36)
		billboard.StudsOffsetWorldSpace = Vector3.new(0, 2.5, 0)
		billboard.AlwaysOnTop = true
		billboard.LightInfluence = 0
		local text_ = Instance.new("TextLabel")
		text_.BackgroundTransparency = 0.3
		text_.BackgroundColor3 = Color3.new(0, 0, 0)
		text_.Size = UDim2.fromScale(1, 1)
		text_.Font = Enum.Font.Arcade
		text_.TextScaled = true
		text_.TextColor3 = color
		text_.Text = text
		text_.Parent = billboard
		billboard.Parent = part
	end
	local function build()
		local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart") :: BasePart?
		if not root then
			return
		end
		local scale = (assets and assets.scale) or 3
		local model = Instance.new("Model")
		model.Name = "McTurnTest"
		local base = root.Position - Vector3.new(0, root.Size.Y / 2, 0)
		local arrow = arrowPicture()
		for row = 0, 1 do
			local face = if row == 0 then Enum.NormalId.Top else Enum.NormalId.Bottom
			for k = 0, 3 do
				local part = Instance.new("Part")
				part.Anchored = true
				part.CanCollide = false
				part.CanQuery = false
				part.Size = Vector3.one * scale
				part.Color = Color3.fromRGB(90, 90, 90)
				-- a row east-west in front (north) of him: top row on the ground, bottom row floating above head height
				part.CFrame = CFrame.new(base + Vector3.new((k - 1.5) * scale * 1.6, if row == 0 then scale * 0.5 else scale * 3.2, -3 * scale))
				local ok, image = pcall(function()
					return AssetService:CreateEditableImage({ Size = Vector2.new(128, 128) })
				end)
				if ok and image then
					local turned = Images.upscale(Images.turn(arrow, k * 90), 8)
					image:WritePixelsBuffer(Vector2.zero, Vector2.new(128, 128), turned.pixels)
					local texture = Instance.new("Texture")
					texture.Face = face
					texture.StudsPerTileU = scale
					texture.StudsPerTileV = scale
					texture.TextureContent = Content.fromObject(image)
					texture.Parent = part
				end
				label(part, (if row == 0 then "oben " else "unten ") .. tostring(k * 90), if row == 0 then Color3.new(1, 1, 0.4)
					else Color3.new(0.5, 0.9, 1))
				part.Parent = model
			end
		end
		-- the red pole in the north (Minecraft: -z), far enough to see where the arrows should point
		local pole = Instance.new("Part")
		pole.Anchored = true
		pole.CanCollide = false
		pole.CanQuery = false
		pole.Size = Vector3.new(0.6, scale * 4, 0.6)
		pole.Color = Color3.fromRGB(220, 30, 30)
		pole.Material = Enum.Material.Neon
		pole.CFrame = CFrame.new(base + Vector3.new(0, scale * 2, -9 * scale))
		label(pole, "N (Norden)", Color3.new(1, 0.3, 0.3))
		pole.Parent = model
		model.Parent = workspace
		board = model
	end
	if calibrateRemote then
		(calibrateRemote :: RemoteEvent).OnClientEvent:Connect(function(kind)
			if kind ~= "calibrate" then
				return
			end
			if board then
				board:Destroy()
				board = nil
			else
				build()
			end
		end)
	end
end

-- "/drehen oben 90": every Top / Bottom picture again, turned
for _, name in ipairs({ "McTopTurn", "McBottomTurn" }) do
	ReplicatedStorage:GetAttributeChangedSignal(name):Connect(function()
		if assets then
			applyAllTextures()
		end
	end)
end

-- region F3: Minecraft's debug screen - frame rate, place, what the world costs here and on the server
do -- (its own block: these locals do not count towards the 200 of the script)
	local Stats = game:GetService("Stats")
	local debugGui = Instance.new("ScreenGui")
	debugGui.Name = "McDebug"
	debugGui.ResetOnSpawn = false
	debugGui.DisplayOrder = 20
	debugGui.Enabled = false
	local text = Instance.new("TextLabel")
	text.BackgroundColor3 = Color3.new(0, 0, 0)
	text.BackgroundTransparency = 0.55
	text.BorderSizePixel = 0
	text.Position = UDim2.fromOffset(4, 4)
	text.AutomaticSize = Enum.AutomaticSize.XY
	text.Font = Enum.Font.Code
	text.TextSize = 14
	text.TextColor3 = Color3.new(1, 1, 1)
	text.TextXAlignment = Enum.TextXAlignment.Left
	text.TextYAlignment = Enum.TextYAlignment.Top
	text.Text = ""
	text.Parent = debugGui
	debugGui.Parent = player:WaitForChild("PlayerGui")
	local parts, textures = 0, 0
	local function counted(item: Instance, step: number)
		if item:IsA("BasePart") then
			parts += step
		elseif item:IsA("Texture") then
			textures += step
		end
	end
	task.spawn(function()
		local world = workspace:WaitForChild("MinecraftWorld", 60)
		if world then
			world.DescendantAdded:Connect(function(item)
				counted(item, 1)
			end)
			world.DescendantRemoving:Connect(function(item)
				counted(item, -1)
			end)
			for _, item in ipairs(world:GetDescendants()) do
				counted(item, 1)
			end
		end
	end)
	local frames, frameTime, worst = 0, 0, 0
	RunService.RenderStepped:Connect(function(dt)
		frames += 1
		frameTime += dt
		worst = math.max(worst, dt)
	end)
	local server: any = nil
	UserInputService.InputBegan:Connect(function(input, processed)
		if input.KeyCode == Enum.KeyCode.F3 and not processed then
			debugGui.Enabled = not debugGui.Enabled
		end
	end)
	task.spawn(function()
		while true do
			task.wait(0.5)
			if not debugGui.Enabled then
				frames, frameTime, worst = 0, 0, 0
				continue
			end
			local statsRemote = remotes:FindFirstChild("WorldStats")
			if statsRemote and statsRemote:IsA("RemoteFunction") then
				task.spawn(function()
					local ok, answer = pcall(function()
						return (statsRemote :: RemoteFunction):InvokeServer()
					end)
					if ok and type(answer) == "table" then
						server = answer
					end
				end)
			end
			local fps = if frameTime > 0 then frames / frameTime else 0
			local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart") :: BasePart?
			local scale = (assets and assets.scale) or 3
			local minY = (assets and assets.minY) or 0
			local lines = {
				string.format("Bridge MinecraftWorld  %d fps (schlechtester Frame %.0f ms)", math.floor(fps + 0.5), worst * 1000),
			}
			if root then
				local p = root.Position
				local bx, by, bz = math.floor(p.X / scale), math.floor(p.Y / scale) + minY - 1, math.floor(p.Z / scale)
				local dim = (by + 128) // 1024 -- (Dims: 1024 blocks per dimension)
				table.insert(lines, string.format("XYZ: %d / %d / %d   Chunk %d %d   Dimension %s", bx, by - dim * 1024, bz,
					bx // 16, bz // 16, if dim == 0 then "Oberwelt" elseif dim == 1 then "Nether" elseif dim == 2 then "End"
						else tostring(dim)))
			end
			local images = 0
			for _ in pairs(cache) do
				images += 1
			end
			table.insert(lines, string.format("Welt hier: %d Parts, %d Texturen, %d Bilder, Textur-Auffrischen wartet: %d",
				parts, textures, images, #refreshQueue))
			table.insert(lines, "Lichter: " .. tostring(player:GetAttribute("McLightsInfo") or "-"))
			local memory, instances, received, sent = 0, 0, 0, 0
			pcall(function()
				memory = Stats:GetTotalMemoryUsageMb()
				instances = Stats.InstanceCount
				received = Stats.DataReceiveKbps
				sent = Stats.DataSendKbps
			end)
			table.insert(lines, string.format("Speicher %.0f MB, %d Instanzen, Netz rein %.0f KB/s raus %.0f KB/s", memory,
				instances, received, sent))
			if server then
				local dims = {}
				for dim, count in pairs(server.byDim or {}) do
					table.insert(dims, string.format("%s %d", if tonumber(dim) == 0 then "Oberwelt" elseif tonumber(dim) == 1
						then "Nether" elseif tonumber(dim) == 2 then "End" else tostring(dim), count))
				end
				table.insert(lines, string.format("Server: %d Chunks (%s), %d Abschnitte, %d Parts, Bau-Warteschlange %d",
					server.chunks or 0, table.concat(dims, ", "), server.sections or 0, server.parts or 0, server.queue or 0))
				table.insert(lines, string.format("Server-Frame %.1f ms (schlechtester %.0f ms), Bauen %.1f ms/Abschnitt, Bridge %d Anfragen/min",
					server.frameMs or 0, server.worstMs or 0, server.buildMs or 0, server.requestsPerMinute or 0))
			end
			text.Text = table.concat(lines, "\n")
			frames, frameTime, worst = 0, 0, 0
		end
	end)
end
-- endregion

-- region start
local function useAssets(newAssets)
	if type(newAssets) ~= "table" then
		return
	end
	local first = assets == nil
	assets = newAssets
	rebuildTabs()
	applyAllTextures()
	refresh()
	rebuildUnknownItems()
	preloadIcons()
	if first then
		showItemName()
		inventoryRemote:FireServer("state") -- (the server sends it when the character comes too)
		local ok, problem = pcall(function()
			require(ReplicatedStorage:WaitForChild("MinecraftSky") :: any).start({
				picture = guiPicture,
				glow = glowPicture,
				assets = function()
					return assets
				end,
				shaderActive = function()
					return Shaders.current() ~= "off"
				end,
			})
		end)
		if not ok then
			warn("[MinecraftWorld] the Minecraft sky could not start: " .. tostring(problem))
		end
	end
end

assetsChanged.OnClientEvent:Connect(useAssets)
-- pictures that could not be made yet (and the GUI with them) get another try every few seconds
task.spawn(function()
	while true do
		task.wait(RETRY)
		if next(waiting) ~= nil or next(failedAt) ~= nil then
			retryWaiting()
			refresh()
		end
	end
end)
if workspace.CurrentCamera then
	workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(function()
		onViewport()
		refresh()
	end)
end
player:GetAttributeChangedSignal("McGameMode"):Connect(refresh)
refresh()
task.spawn(function()
	-- The server may still be loading the world: ask until it has the pictures (AssetsChanged also brings them)
	while assets == nil do
		local ok, result = pcall(function()
			return getAssets:InvokeServer()
		end)
		if ok and result then
			useAssets(result)
		else
			task.wait(2)
		end
	end
end)
-- endregion

-- region armor on every character (Roblox players + Minecraft players: attribute McArmorItems "head|chest|legs|feet"):
-- Minecraft's armor model (HumanoidModel 1 px bigger, leggings 0.5 px) in the colour of its material
do
	local PIXEL = 3 / 16 * 0.9375
	local MATERIALS = {
		leather = Color3.fromRGB(160, 101, 64), chainmail = Color3.fromRGB(140, 140, 145), iron = Color3.fromRGB(216, 216, 216),
		golden = Color3.fromRGB(250, 222, 77), diamond = Color3.fromRGB(92, 219, 213), netherite = Color3.fromRGB(68, 58, 59),
		copper = Color3.fromRGB(196, 110, 80), turtle = Color3.fromRGB(71, 191, 74),
	}
	-- slot -> {limb, grow (px), part of the limb (from, to: 0 = its top, 1 = its bottom)}
	local PIECES = {
		{ { "Head", 1, 0, 1 } },
		{ { "Body", 1, 0, 1 }, { "RightArm", 1, 0, 1 }, { "LeftArm", 1, 0, 1 } },
		{ { "Body", 0.5, 0.55, 1 }, { "RightLeg", 0.5, 0, 0.75 }, { "LeftLeg", 0.5, 0, 0.75 } },
		{ { "RightLeg", 1, 0.6, 1 }, { "LeftLeg", 1, 0.6, 1 } },
	}
	local function materialOf(id: string): (Color3?, Enum.Material)
		local name = string.match(id, ":([%w_]+)$") or id
		for key, color in pairs(MATERIALS) do
			if string.find(name, key, 1, true) == 1 then
				return color, if key == "chainmail" then Enum.Material.DiamondPlate elseif key == "golden" or key == "iron"
					or key == "netherite" or key == "copper" then Enum.Material.Metal else Enum.Material.SmoothPlastic
			end
		end
		return nil, Enum.Material.SmoothPlastic
	end
	local function dress(model: Model)
		for _, old in ipairs(model:GetChildren()) do
			if old.Name == "McArmorPiece" then
				old:Destroy()
			end
		end
		local text = model:GetAttribute("McArmorItems")
		if type(text) ~= "string" or model:GetAttribute("McInvisible") == true then
			return
		end
		local slot = 0
		for id in string.gmatch(text .. "|", "([^|]*)|") do
			slot += 1
			local color, material = materialOf(id)
			if id == "" or not color or not PIECES[slot] then
				continue
			end
			for _, piece in ipairs(PIECES[slot]) do
				local limb = model:FindFirstChild(piece[1])
				if not limb or not limb:IsA("BasePart") then
					continue
				end
				local grow = piece[2] * 2 * PIXEL
				local size = limb.Size
				local from, to = piece[3], piece[4]
				local height = size.Y * (to - from)
				local part = Instance.new("Part")
				part.Name = "McArmorPiece"
				part.Color = color
				part.Material = material
				part.CanCollide = false
				part.CanQuery = false
				part.CanTouch = false
				part.Massless = true
				part.Size = Vector3.new(size.X + grow, height + (if from == 0 then grow / 2 else 0) + (if to == 1 then grow / 2 else 0),
					size.Z + grow)
				local middle = size.Y / 2 - size.Y * (from + to) / 2 -- (from the limb's middle, up = +)
				local shift = (if from == 0 then grow / 4 else 0) - (if to == 1 then grow / 4 else 0)
				part.CFrame = limb.CFrame * CFrame.new(0, middle + shift, 0)
				local weld = Instance.new("WeldConstraint")
				weld.Part0 = limb
				weld.Part1 = part
				weld.Parent = part
				part.Parent = model
			end
		end
	end
	local watched = setmetatable({}, { __mode = "k" })
	local function watch(model: Instance)
		if not model:IsA("Model") or watched[model] then
			return
		end
		watched[model] = true
		model:GetAttributeChangedSignal("McArmorItems"):Connect(function()
			dress(model)
		end)
		model:GetAttributeChangedSignal("McInvisible"):Connect(function()
			dress(model)
		end)
		if model:GetAttribute("McArmorItems") then
			task.defer(dress, model)
		end
	end
	workspace.DescendantAdded:Connect(function(item)
		if item:IsA("Model") and item:GetAttribute("McSkinUser") ~= nil then
			watch(item)
		end
	end)
	-- (a model can get McSkinUser after it came into the workspace)
	task.spawn(function()
		while true do
			task.wait(2)
			for _, other in ipairs(Players:GetPlayers()) do
				if other.Character then
					watch(other.Character)
				end
			end
			local npcs = workspace:FindFirstChild("BridgeRemotePlayers") -- (the Minecraft players)
			for _, item in ipairs(if npcs then npcs:GetChildren() else {}) do
				watch(item)
			end
		end
	end)
end
-- endregion
