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
local cache = {} -- cache key -> {image = EditableImage, content = Content, source = string}
local failedAt = {} -- cache key -> os.clock() of the last failure
local waiting = setmetatable({}, { __mode = "k" }) -- Texture -> true: still without its picture
local RETRY = 2 -- seconds

local function makeImage(cacheKey: string, source: string, build: () -> any): Content?
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
		local content = makeImage(cacheKey, tostring(texture), function()
			return Images.upscale(frameOf(texture, 0), ANIMATED_SCALE)
		end)
		local entry = animations[cacheKey]
		if content and (not entry or entry.texture ~= texture) then
			animations[cacheKey] = { texture = texture, frames = {}, shown = 0 }
		end
		return content
	end
	local quarter = ((turn or 0) // 90) % 4
	return makeImage("world:" .. tostring(key) .. (if quarter ~= 0 then "@" .. quarter else ""), buffer.tostring(texture.pixels),
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
	return if texture.Face == Enum.NormalId.Top then TOP_TURN elseif texture.Face == Enum.NormalId.Bottom then BOTTOM_TURN else 0
end

local function showAgain(key: string)
	local plain = worldContent(key)
	if not plain then
		return
	end
	for texture in pairs(shownBy[key] or {}) do
		if texture.Parent then
			local content = worldContent(key, turnOf(texture)) or plain
			texture.TextureContent = Content.none
			texture.TextureContent = content
		end
	end
	local holder = holders[key]
	if holder then
		holder.TextureContent = Content.none
		holder.TextureContent = plain
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
		pcall(function()
			texture.ResampleMode = Enum.ResamplerMode.Pixelated
		end)
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
	if next(lost) ~= nil then
		local keys = lost
		lost = {}
		for key in pairs(keys) do
			showAgain(key)
		end
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
itemName.Position = UDim2.new(0.5, 0, 0, -26) -- above the hearts
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

-- creative: 9 x 5 items (scrolling), the hotbar row below, the scroll bar on the right, two tabs above
local CREATIVE_ROWS = 5
local creativeScroll = 0 -- first row shown
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
		local item = assets and assets.items and assets.items[creativeScroll * 9 + index + 1]
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

-- the two tabs: all items / the normal inventory (Minecraft's "Survival Inventory" tab)
local tabs = {}
local setView -- below
for index, view in ipairs({ "creative", "survival" }) do
	local tab = image(dim, "Tab" .. view, 0, 0, 26, 32, 12)
	tab.AnchorPoint = Vector2.new(0, 1)
	scaled(tab)
	local tabIcon = image(tab, "Icon", 5, 9, 16, 16, 13)
	tabIcon.ResampleMode = Enum.ResamplerMode.Default
	local button = Instance.new("TextButton")
	button.Text = ""
	button.BackgroundTransparency = 1
	button.Size = UDim2.fromScale(1, 1)
	button.ZIndex = 14
	button.Parent = tab
	button.MouseButton1Click:Connect(function()
		setView(view)
	end)
	tabs[index] = { frame = tab, icon = tabIcon, view = view, index = index }
end

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

local function creativeRows(): number
	local count = assets and assets.items and #assets.items or 0
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
		local item = assets and assets.items and assets.items[creativeScroll * 9 + index]
		showStack(view, if item then { id = item.id, n = 1 } else nil)
	end
	local rows = creativeRows()
	setPicture(scroller, if rows > 0 then gui("scroller") else gui("scroller_disabled") or gui("scroller"))
	scroller.BackgroundTransparency = if gui("scroller") then 1 else 0.2
	scroller.Position = UDim2.fromOffset(175, 18 + (if rows > 0 then math.floor(creativeScroll / rows * (112 - 15) + 0.5) else 0))
	window.Visible = inventoryView == "survival"
	creative.Visible = inventoryView == "creative"
	local isCreative = gameMode() == "creative"
	local scale = guiScale()
	for _, tab in ipairs(tabs) do
		tab.frame.Visible = inventoryOpen and isCreative
		local chosen = tab.view == inventoryView
		local picture = if chosen then gui("tab_selected") else gui("tab")
		setPicture(tab.frame, picture)
		tab.frame.BackgroundTransparency = if picture then 1 else (if chosen then 0 else 0.4)
		tab.frame.ZIndex = if chosen then 16 else 12
		-- above the top left corner of the open window (Minecraft: the tabs stand on the window)
		local width = if inventoryView == "creative" then 195 else 176
		local height = if inventoryView == "creative" then 136 else 166
		tab.frame.Position = UDim2.new(0.5, (-width / 2 + (tab.index - 1) * 27) * scale, 0.5, (-height / 2 + 4) * scale)
		setPicture(tab.icon, iconContent(if tab.view == "creative" then "minecraft:grass_block" else "minecraft:crafting_table"))
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
	local item = assets and assets.items and assets.items[creativeScroll * 9 + index + 1]
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

local function setInventory(open: boolean)
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
local function scrollCreative(step: number)
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
	refresh()
	if first then
		showItemName()
	end
end)
-- endregion

-- region building: aim, use, break (with Minecraft's breaking time in survival)
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

local target = nil -- the block under the crosshair: {x, y, z, normal, face, hit, name, part, box, parts}
local targetNpc = nil -- or the NPC of a Minecraft player under the crosshair (left click hits him)

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
local function direction(normal: Vector3): string
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
	rayParams.FilterDescendantsInstances = if npcFolder then { worldFolder, npcFolder } else { worldFolder }
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
	if y < assets.minY or y >= assets.maxY then
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

local function act(action: string, repeated: boolean?)
	local mode = gameMode()
	if mode == "spectator" then
		return
	end
	if action == "break" then
		if targetNpc then
			swingArm()
			attackRemote:FireServer(targetNpc) -- hit the Minecraft player (Minecraft does the damage)
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
		act("use")
		held.use = os.clock()
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
	if held.use and now - held.use >= REPEAT_USE then
		held.use = now
		act("use", true)
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
-- endregion


-- region items lying in the world (Minecraft's item entities - the server puts an invisible part where each lies)
--[[
	Drawn like Minecraft: blocks as small cubes / models (a quarter of a block), flat items (redstone, sticks, tools)
	as a picture half a block big; turning slowly (1 radian per second), bobbing (0.1 blocks), more copies for bigger
	stacks (2-16: 2, up to 32: 3, up to 48: 4, more: 5). Picked up (by anybody - Minecraft decides who, once): the
	item flies to whoever is closest and is gone.
]]
local FACE_NORMALS = { up = Enum.NormalId.Top, down = Enum.NormalId.Bottom, north = Enum.NormalId.Front,
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

local function itemPiece(parent: Instance, size: Vector3, cframe: CFrame, faces: { [string]: string })
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
local flying = {}
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
local function rebuildUnknownItems()
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
-- endregion

-- region preparing the icons: all at once in the background (the inventory then shows every icon right away)
local preloading, preloadAgain = false, false
local function preloadIcons()
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
-- endregion

-- region settings (M): field of view + shaders - only for this player, nothing goes to Minecraft or the others
local refreshMenu -- below
local Shaders = require(ReplicatedStorage:WaitForChild("MinecraftShaders") :: any)
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

local function label(parent: Instance, text: string, y: number, color: Color3?): TextLabel
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
-- endregion

-- region health: hearts, fall damage, getting hit
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

local function updateHearts()
	local mode = gameMode()
	local survival = mode == "survival" or mode == "adventure" -- (creative / spectator: no hearts, like Minecraft)
	for _, heart in ipairs(hearts) do
		heart.container.Visible = survival
	end
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
	if player:GetAttribute("McFluid") ~= nil then
		fallPeak = nil -- (Minecraft: in water / lava the fall starts new - landing in water does not hurt)
		return
	end
	local humanoidState = humanoid:GetState()
	local y = root.Position.Y
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
-- endregion

-- region start
local function useAssets(newAssets)
	if type(newAssets) ~= "table" then
		return
	end
	local first = assets == nil
	assets = newAssets
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
