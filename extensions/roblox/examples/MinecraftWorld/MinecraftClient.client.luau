--[[
	MinecraftClient - the Minecraft side of the player (LocalScript in StarterPlayerScripts)

	- Textures: the server got the pictures from Minecraft (RemoteFunction GetAssets). EditableImages only exist on
	  the client, so they are made here and put on every Texture with the attribute "McTexture" in the world - and the
	  skins (RemoteFunction GetSkin) on every body part with "McSkinFace". Every picture is made once and kept; one
	  that fails is tried again (no grey blocks any more). Studio / game: Game Settings > Security > "Allow Mesh /
	  Image APIs" must be on.
	- Hotbar (keys 1-9, mouse wheel) and inventory (E) with Minecraft's own GUI pictures. Creative mode: items never
	  run out. Click a slot in the inventory to pick an item up, click another one to put it down (or swap).
	- Health like Minecraft: 10 hearts over the hotbar, fall damage (more than 3 blocks), left click on a Minecraft
	  player hits him, hits from Minecraft players come with a red flash, a tilted camera and knockback.
	- Building: left click breaks the block you look at (hold = repeat), right click places the selected item - aimed
	  from the eyes like in Minecraft (MinecraftPlayer says where they are and where they look).
	  The server checks it and sends it to Minecraft over Bridge.
	Camera, walking, sneaking / sprinting, the animations and the chat: MinecraftPlayer.
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
local getSkin = remotes:WaitForChild("GetSkin") :: RemoteFunction

local player = Players.LocalPlayer
local REACH = 5 -- blocks from the eyes, like Minecraft in creative mode
local REPEAT = 0.25 -- seconds between two actions while a mouse button is held
local TEXTURE_SCALE = 8 -- world textures: every Minecraft pixel becomes 8x8 (sharp also where Roblox smooths)
local ICON_SIZE = 128
local HOTBAR_KEYS = {
	[Enum.KeyCode.One] = 1, [Enum.KeyCode.Two] = 2, [Enum.KeyCode.Three] = 3, [Enum.KeyCode.Four] = 4,
	[Enum.KeyCode.Five] = 5, [Enum.KeyCode.Six] = 6, [Enum.KeyCode.Seven] = 7, [Enum.KeyCode.Eight] = 8,
	[Enum.KeyCode.Nine] = 9,
}

local assets = nil -- what the server sent (see MinecraftWorld: clientAssets)
local imagesFailed = false -- the very first picture failed: "Allow Mesh / Image APIs" is off

-- region inventory state: slots 1-9 = hotbar, 10-36 = the three rows above
local slots = table.create(36) :: { any }
local selected = 1
local cursorItem = nil
local inventoryOpen = false

local function itemById(id)
	for _, item in ipairs(assets and assets.items or {}) do
		if item.id == id then
			return item
		end
	end
	return nil
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

local function worldContent(key: any): Content?
	local texture = type(key) == "string" and assets and assets.textures and assets.textures[key]
	if not texture then
		return nil
	end
	return makeImage("world:" .. tostring(key), buffer.tostring(texture.pixels), function()
		return Images.upscale(texture, TEXTURE_SCALE)
	end)
end

local function guiPicture(key: string): Content?
	local texture = assets and assets.textures and assets.textures[key]
	if not texture then
		return nil
	end
	return makeImage("gui:" .. key, buffer.tostring(texture.pixels), function()
		return texture
	end)
end

local function iconContent(item): Content?
	local textures = assets and assets.textures or {}
	local look = item.block and assets and assets.blocks and assets.blocks[item.block]
	local faces = look and look.faces or {}
	local top, north, east = textures[faces.up], textures[faces.north], textures[faces.east]
	if top and north and east then
		local source = buffer.tostring(top.pixels) .. buffer.tostring(north.pixels) .. buffer.tostring(east.pixels)
		return makeImage("icon:" .. item.id, source, function()
			return Images.blockIcon(top, north, east, ICON_SIZE)
		end)
	end
	return makeImage("icon:" .. item.id, "plain", function()
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

local function showAgain(key: string)
	local content = worldContent(key)
	if not content then
		return
	end
	for texture in pairs(shownBy[key] or {}) do
		if texture.Parent then
			texture.TextureContent = Content.none
			texture.TextureContent = content
		end
	end
	local holder = holders[key]
	if holder then
		holder.TextureContent = Content.none
		holder.TextureContent = content
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
		content = worldContent(key)
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
local hotbarIcons = {}
for slot = 1, 9 do
	hotbarIcons[slot] = image(hotbar, "Slot" .. slot, 3 + (slot - 1) * 20, 3, 16, 16, 2)
	hotbarIcons[slot].ResampleMode = Enum.ResamplerMode.Default -- the icons are bigger pictures: smooth
end
local selection = image(hotbar, "Selection", -1, -1, 24, 23, 3)
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

-- Inventory: Minecraft's 176 x 166 window in the middle
local dim = Instance.new("Frame")
dim.Name = "Inventory"
dim.BackgroundColor3 = Color3.new(0, 0, 0)
dim.BackgroundTransparency = 0.45
dim.Size = UDim2.fromScale(1, 1)
dim.Visible = false
dim.ZIndex = 10
dim.Parent = screen
local window = Instance.new("Frame")
window.Name = "Window"
window.AnchorPoint = Vector2.new(0.5, 0.5)
window.Position = UDim2.fromScale(0.5, 0.5)
window.Size = UDim2.fromOffset(176, 166)
window.BackgroundTransparency = 1
window.ZIndex = 11
window.Parent = dim
scaled(window)
local windowBack = image(window, "Background", 0, 0, 176, 166, 11)
local preview = Instance.new("ViewportFrame") -- the player in the black box, like in Minecraft
preview.Name = "Player"
preview.BackgroundTransparency = 1
preview.Position = UDim2.fromOffset(26, 8)
preview.Size = UDim2.fromOffset(49, 70)
preview.ZIndex = 12
preview.Parent = window

local slotButtons = {}
local slotIcons = {}
local hovered = nil
local highlight = Instance.new("Frame")
highlight.Name = "Highlight"
highlight.BackgroundColor3 = Color3.new(1, 1, 1)
highlight.BackgroundTransparency = 0.55
highlight.BorderSizePixel = 0
highlight.Size = UDim2.fromOffset(16, 16)
highlight.Visible = false
highlight.ZIndex = 14
highlight.Parent = window

local function slotPosition(slot: number): (number, number)
	if slot <= 9 then
		return 8 + (slot - 1) * 18, 142 -- hotbar row of the inventory
	end
	local index = slot - 10
	return 8 + (index % 9) * 18, 84 + (index // 9) * 18
end

local refresh -- defined below

local function clickSlot(slot: number)
	if cursorItem == nil then
		cursorItem, slots[slot] = slots[slot], nil
	elseif slots[slot] == nil then
		slots[slot], cursorItem = cursorItem, nil
	else
		slots[slot], cursorItem = cursorItem, slots[slot]
	end
	refresh()
end

for slot = 1, 36 do
	local x, y = slotPosition(slot)
	local button = Instance.new("TextButton")
	button.Name = "Slot" .. slot
	button.Text = ""
	button.BackgroundTransparency = 1
	button.Position = UDim2.fromOffset(x - 1, y - 1)
	button.Size = UDim2.fromOffset(18, 18)
	button.ZIndex = 15
	button.Parent = window
	button.MouseButton1Click:Connect(function()
		clickSlot(slot)
	end)
	button.MouseEnter:Connect(function()
		hovered = slot
		highlight.Position = UDim2.fromOffset(x, y)
		highlight.Visible = true
	end)
	button.MouseLeave:Connect(function()
		if hovered == slot then
			hovered = nil
			highlight.Visible = false
		end
	end)
	slotButtons[slot] = button
	local icon = image(window, "Icon" .. slot, x, y, 16, 16, 13)
	icon.ResampleMode = Enum.ResamplerMode.Default
	slotIcons[slot] = icon
end

-- the item on the mouse while moving it around
local cursor = image(screen, "CursorItem", 0, 0, 16, 16, 30)
cursor.AnchorPoint = Vector2.new(0.5, 0.5)
cursor.ResampleMode = Enum.ResamplerMode.Default
cursor.Visible = false

local function gui(name: string): Content?
	local key = assets and assets.gui and assets.gui[name]
	return if key then guiPicture(key) else nil
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
	selection.Position = UDim2.fromOffset(-1 + (selected - 1) * 20, -1)
	for slot = 1, 36 do
		local item = slots[slot]
		local content = if item then iconContent(item) else nil
		setPicture(slotIcons[slot], content)
		if slot <= 9 then
			setPicture(hotbarIcons[slot], content)
		end
	end
	setPicture(cursor, if cursorItem then iconContent(cursorItem) else nil)
	cursor.Visible = inventoryOpen and cursorItem ~= nil
	local scale = guiScale()
	cursor.Size = UDim2.fromOffset(16 * scale, 16 * scale)
end

local function showItemName()
	local item = slots[selected]
	itemName.Text = item and item.name or ""
	nameShownAt = os.clock()
end

local function select(slot: number)
	selected = slot
	refresh()
	showItemName()
end
-- endregion

-- region inventory open / close
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

local function setInventory(open: boolean)
	if inventoryOpen == open then
		return
	end
	inventoryOpen = open
	dim.Visible = open
	player:SetAttribute("McGuiOpen", open) -- MinecraftPlayer frees the mouse and stops walking
	if open then
		updatePreview()
		ContextActionService:BindActionAtPriority("MinecraftInventory", blockMovement, false,
			Enum.ContextActionPriority.High.Value, Enum.KeyCode.W, Enum.KeyCode.A, Enum.KeyCode.S, Enum.KeyCode.D,
			Enum.KeyCode.Space, Enum.KeyCode.Up, Enum.KeyCode.Down, Enum.KeyCode.Left, Enum.KeyCode.Right)
	else
		ContextActionService:UnbindAction("MinecraftInventory")
		if cursorItem then
			-- put the item on the mouse back into the first free slot (Minecraft would throw it on the ground)
			for slot = 1, 36 do
				if slots[slot] == nil then
					slots[slot] = cursorItem
					break
				end
			end
			cursorItem = nil
		end
		hovered = nil
		highlight.Visible = false
	end
	refresh()
end
-- endregion

-- region building
local selectionPart = Instance.new("Part")
selectionPart.Name = "MinecraftBlockSelection"
selectionPart.Anchored = true
selectionPart.CanCollide = false
selectionPart.CanQuery = false
selectionPart.CanTouch = false
selectionPart.Transparency = 1
selectionPart.Parent = workspace
local selectionBox = Instance.new("SelectionBox")
selectionBox.Adornee = selectionPart
selectionBox.Color3 = Color3.new(0, 0, 0)
selectionBox.LineThickness = 0.03
selectionBox.SurfaceTransparency = 1
selectionBox.Transparency = 0.35
selectionBox.Visible = false
selectionBox.Parent = selectionPart

local rayParams = RaycastParams.new()
rayParams.FilterType = Enum.RaycastFilterType.Include

local target = nil -- {x, y, z, normal = Vector3} of the block under the mouse
local targetNpc = nil -- or the NPC of a Minecraft player under the mouse (left click hits him)

local function blockOf(position: Vector3): (number, number, number)
	local scale = assets.scale
	return math.floor(position.X / scale), math.floor(position.Y / scale) + assets.minY, math.floor(position.Z / scale)
end

local function blockCenter(x: number, y: number, z: number): Vector3
	local scale = assets.scale
	return Vector3.new((x + 0.5) * scale, (y - assets.minY + 0.5) * scale, (z + 0.5) * scale)
end

local function findTarget()
	target = nil
	targetNpc = nil
	local worldFolder = workspace:FindFirstChild("MinecraftWorld")
	local character = player.Character
	local head = character and (character:FindFirstChild("Head") or character:FindFirstChild("HumanoidRootPart"))
	local camera = workspace.CurrentCamera
	if not assets or not worldFolder or not head or not camera or inventoryOpen then
		return
	end
	-- Like Minecraft: from the eyes where the player looks (also in third person / front view) - MinecraftPlayer says
	-- where that is; without it the middle of the screen
	local eye, look = player:GetAttribute("McEye"), player:GetAttribute("McLook")
	local origin, direction
	if typeof(eye) == "Vector3" and typeof(look) == "Vector3" then
		origin, direction = eye, look.Unit
	else
		local ray = camera:ViewportPointToRay(camera.ViewportSize.X / 2, camera.ViewportSize.Y / 2)
		origin, direction = ray.Origin, ray.Direction
	end
	local npcFolder = workspace:FindFirstChild("BridgeRemotePlayers")
	rayParams.FilterDescendantsInstances = if npcFolder then { worldFolder, npcFolder } else { worldFolder }
	local result = workspace:Raycast(origin, direction * (REACH + 1) * assets.scale, rayParams)
	if not result then
		return
	end
	if npcFolder and result.Instance:IsDescendantOf(npcFolder) then
		local model = result.Instance:FindFirstAncestorOfClass("Model")
		while model and model:GetAttribute("McUserId") == nil do
			model = model:FindFirstAncestorOfClass("Model")
		end
		if model and (result.Position - origin).Magnitude <= (REACH + 0.5) * assets.scale then
			targetNpc = model
		end
		return
	end
	local x, y, z = blockOf(result.Position - result.Normal * 0.05)
	if (result.Position - origin).Magnitude > REACH * assets.scale then
		return
	end
	local normal = Vector3.new(math.round(result.Normal.X), math.round(result.Normal.Y), math.round(result.Normal.Z))
	target = { x = x, y = y, z = z, normal = normal }
end

-- Would a block at x, y, z stand in my own character?
local function inMyCharacter(x: number, y: number, z: number): boolean
	local character = player.Character
	if not character then
		return false
	end
	local box, size = character:GetBoundingBox()
	local center = blockCenter(x, y, z)
	local half = assets.scale / 2
	local delta = center - box.Position
	return math.abs(delta.X) < half + size.X / 2 - 0.1 and math.abs(delta.Y) < half + size.Y / 2 - 0.1
		and math.abs(delta.Z) < half + size.Z / 2 - 0.1
end

-- My own arm swings when I hit / build: the script MinecraftPlayer plays Minecraft's swing (replicates to the others);
-- the server tells Minecraft ("sw": the mannequin swings too)
local function swingArm()
	player:SetAttribute("McSwingAt", os.clock())
end

local function act(action: string)
	if (action == "break" and (targetNpc or target)) or (action == "place" and target and slots[selected]) then
		swingArm()
	end
	if action == "break" and targetNpc then
		attackRemote:FireServer(targetNpc) -- hit the Minecraft player (Minecraft does the damage)
		return
	end
	if not target then
		return
	end
	if action == "break" then
		editRemote:FireServer("break", target.x, target.y, target.z)
	else
		local item = slots[selected]
		if not item or not item.block then
			return
		end
		local x, y, z = target.x + target.normal.X, target.y + target.normal.Y, target.z + target.normal.Z
		if inMyCharacter(x, y, z) then
			return
		end
		editRemote:FireServer("place", x, y, z, item.id)
	end
end

local held = {} -- "break" / "place" -> time of the last action while the button is held

UserInputService.InputBegan:Connect(function(input, processed)
	if input.KeyCode == Enum.KeyCode.E and not processed then
		setInventory(not inventoryOpen)
		return
	end
	if processed or inventoryOpen then
		return
	end
	local slot = HOTBAR_KEYS[input.KeyCode]
	if slot then
		select(slot)
	elseif input.UserInputType == Enum.UserInputType.MouseButton1 then
		findTarget()
		act("break")
		held["break"] = os.clock()
	elseif input.UserInputType == Enum.UserInputType.MouseButton2 then
		-- the mouse is always caught like in Minecraft (MinecraftPlayer): the right button only places
		findTarget()
		act("place")
		held.place = os.clock()
	end
end)
UserInputService.InputEnded:Connect(function(input)
	if input.UserInputType == Enum.UserInputType.MouseButton1 then
		held["break"] = nil
	elseif input.UserInputType == Enum.UserInputType.MouseButton2 then
		held.place = nil
	end
end)
-- the mouse wheel goes through the hotbar (like Minecraft)
UserInputService.InputChanged:Connect(function(input, processed)
	if processed or inventoryOpen or input.UserInputType ~= Enum.UserInputType.MouseWheel then
		return
	end
	local step = if input.Position.Z > 0 then -1 elseif input.Position.Z < 0 then 1 else 0
	if step ~= 0 then
		select((selected - 1 + step) % 9 + 1)
	end
end)

RunService.RenderStepped:Connect(function()
	findTarget()
	if target then
		selectionPart.Size = Vector3.one * (assets.scale + 0.04)
		selectionPart.CFrame = CFrame.new(blockCenter(target.x, target.y, target.z))
		selectionBox.Visible = true
	else
		selectionBox.Visible = false
	end
	local now = os.clock()
	for action, at in pairs(held) do
		if now - at >= REPEAT then
			held[action] = now
			act(action)
		end
	end
	if inventoryOpen then
		UserInputService.MouseBehavior = Enum.MouseBehavior.Default
		UserInputService.MouseIconEnabled = true
		if cursorItem then
			local mouse = UserInputService:GetMouseLocation()
			cursor.Position = UDim2.fromOffset(mouse.X, mouse.Y)
		end
	end
	-- the item name above the hotbar fades out after 2 s (like Minecraft)
	local age = now - nameShownAt
	itemName.TextTransparency = if age < 1.5 then 0 elseif age < 2 then (age - 1.5) * 2 else 1
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
	local state = humanoid:GetState()
	local y = root.Position.Y
	if FALLING[state] then
		fallPeak = math.max(fallPeak or y, y)
	elseif fallPeak then
		local blocks = (fallPeak - y) / (assets and assets.scale or 3)
		fallPeak = nil
		if blocks > 3 and state ~= Enum.HumanoidStateType.Swimming and state ~= Enum.HumanoidStateType.Climbing then
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
	if first then
		-- Creative mode: every item once - the first 9 in the hotbar, the others in the inventory above
		for index, item in ipairs(assets.items or {}) do
			if index <= 36 then
				slots[index] = item
			end
		end
	else
		-- keep where the player put things, with the new item data
		for slot = 1, 36 do
			if slots[slot] then
				slots[slot] = itemById(slots[slot].id)
			end
		end
	end
	applyAllTextures()
	refresh()
	if first then
		showItemName()
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
