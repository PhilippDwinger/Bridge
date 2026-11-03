--!strict
--[[
	MinecraftSky - day, night, weather and light like Minecraft (ModuleScript "MinecraftSky" in ReplicatedStorage,
	started by the LocalScript MinecraftClient; only on this client, nothing here decides anything)

	Minecraft sends its own sky values (topic mcworld.sky -> attributes "Mc..." of Lighting, set by the server): the
	time, the angles of sun / moon, the colours of sky, fog, clouds, sunrise, the sky light (1 by day .. 0.24 at night),
	rain / thunder and whether it rains or snows here. Out of that:

	- Lighting: the clock (sun and moon where Minecraft has them), brightness like Minecraft's light map (gamma 0.5:
	  bright day, dark blue night), no reflections, soft shadows where the sky does not reach (caves stay dark)
	- Atmosphere: the horizon in Minecraft's fog colour, the sky above in its sky colour; under water / in lava
	  Minecraft's water / lava fog
	- Minecraft's square sun and its moon (in the right phase) - BillboardGuis far away where Roblox' sun / moon are
	  (their black made see-through: Minecraft adds them onto the sky, so no box around them)
	- Minecraft's clouds: its cloud picture at cloud height, drifting east (0.6 blocks/s), in the cloud colour
	- rain / snow like Minecraft's weather renderer: around the camera one falling picture per block column (radius 5),
	  from the ground up, seen from every side, fading towards the edge
	- stars at night (Roblox' stars, as many as Minecraft's star brightness)

	    Sky.start({ picture = function(key) -> Content?, glow = function(key) -> Content?, assets = function() -> assets?,
	        shaderActive = function() -> bool })

	The pure helpers (tests): Sky.clockTime(sunAngle), Sky.brightness(skyLight).
]]
local Lighting = game:GetService("Lighting")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

local Sky = {}
Sky.effects = {} :: { [string]: any } -- id -> {amp, dur, ...}: the player's status effects (MinecraftPlayer fills it)

local BLOCK = 3 -- studs per block (MinecraftCharacter.STUDS_PER_BLOCK)
local CELESTIAL_DISTANCE = 1500 -- studs: sun and moon are this far away (they keep their size in degrees)
local SUN_SIZE = 0.6 -- Minecraft: the sun is 30 x 2 units at 100 away
local MOON_SIZE = 0.4 -- the moon 20 x 2 units
local CLOUD_TILE_BLOCKS = 256 * 12 -- Minecraft: one pixel of clouds.png = 12 x 12 blocks
local CLOUD_SPEED = 0.03 * 20 -- blocks per second towards east (CloudRenderer: ticks x 0.03)
local CLOUD_SIZE = 2048 -- studs (Roblox' biggest part)
local WEATHER_RADIUS = 5 -- blocks around the camera (Minecraft: 5 "fast", 10 "fancy")
local WEATHER_HEIGHT = 10 -- blocks above and below the camera
local GROUND_EVERY = 0.5 -- seconds: the ground under the rain columns is looked for again
local SMOOTH = 1.2 -- per second: how quickly colours / light follow Minecraft's (it sends once a second)

--[[
	Minecraft's light map (LightTexture, brightness setting 50 %): light level L (0..15) -> how bright, 0..1.
	curve = l / (4 - 3 l) with l = L / 15, then halfway to 1 - (1 - curve)^4 (the gamma).
]]
function Sky.brightness(skyLight: number): number
	local l = math.clamp(skyLight, 0, 1)
	local curve = l / (4 - 3 * l)
	local bright = 1 - (1 - curve) ^ 4
	return curve + (bright - curve) * 0.5
end

--- Minecraft's sun angle (degrees, 0 = noon, 90 = sunset, 180 = midnight) -> Roblox' ClockTime (hours).
function Sky.clockTime(sunAngle: number): number
	return (12 + sunAngle / 15) % 24
end

local function attribute(name: string, fallback: any): any
	local value = Lighting:GetAttribute(name)
	if value == nil then
		return fallback
	end
	return value
end

-- region the other dimensions: each lies at its own height (assets.dims); their sky comes in McDimSky (JSON: index ->
-- {skybox, ceiling, sky, fog, ambient, skyLight, stars, waterFog, waterColor ...} sampled by Minecraft where a
-- player of that dimension stands). The Nether: no sun, moon, clouds or rain - its biome fog all around. The End: dark.
local dimSkyText = ""
local dimSky: { [string]: any } = {}
local current: any = nil -- the entry of the dimension the camera is in (nil = the overworld)
local currentKind = "overworld"

local function rgbOf(value: any, fallback: Color3): Color3
	if type(value) == "table" and #value >= 3 then
		return Color3.fromRGB(tonumber(value[1]) or 0, tonumber(value[2]) or 0, tonumber(value[3]) or 0)
	end
	return fallback
end

local DIM_NAMES: { [string]: { string } } = {
	McSkyColor = { "sky", "color" }, McFogColor = { "fog", "color" }, McSkyLightColor = { "skyLightColor", "color" },
	McWaterFogColor = { "waterFog", "color" }, McWaterColor = { "waterColor", "color" },
	McSkyLight = { "skyLight", "number" }, McStarBrightness = { "stars", "number" },
}
local DIM_NONE: { [string]: any } = {
	McRain = 0, McThunder = 0, McPrecipitation = "none", McSunriseAlpha = 0, McCloudAlpha = 0,
}

local function dimAttribute(name: string, fallback: any): any
	if not current then
		return attribute(name, fallback)
	end
	local none = DIM_NONE[name]
	if none ~= nil then
		return none
	end
	local mapped = DIM_NAMES[name]
	if mapped then
		local value = current[mapped[1]]
		if mapped[2] == "color" then
			return rgbOf(value, if typeof(fallback) == "Color3" then fallback else Color3.new())
		end
		return if type(value) == "number" then value else fallback
	end
	return attribute(name, fallback)
end

-- Which dimension the camera is in (its height band, like the mod's Dims: band 1024 blocks, from y - 128)
local function updateDimension(assets: any, eyeY: number, scale: number)
	local dims = assets and assets.dims
	if type(dims) ~= "table" or #dims <= 1 then
		current, currentKind = nil, "overworld"
		return
	end
	local blockY = math.floor(eyeY / scale) + (assets.minY or -64)
	local d = math.clamp((blockY + 128) // 1024, 0, #dims - 1)
	local entry = dims[d + 1]
	if d == 0 or type(entry) ~= "table" then
		current, currentKind = nil, "overworld"
		return
	end
	local text = Lighting:GetAttribute("McDimSky")
	if type(text) == "string" and text ~= dimSkyText then
		dimSkyText = text
		local ok, decoded = pcall(function()
			return game:GetService("HttpService"):JSONDecode(text)
		end)
		dimSky = if ok and type(decoded) == "table" then decoded else {}
	end
	currentKind = tostring(entry.kind or "nether")
	current = dimSky[tostring(d)] or {
		-- (not from Minecraft yet: its usual look)
		fog = if currentKind == "end" then { 10, 10, 16 } else { 51, 8, 8 },
		sky = if currentKind == "end" then { 0, 0, 0 } else { 51, 8, 8 },
		skyLight = 0, stars = 0,
	}
end
-- endregion

local function lerpColor(a: Color3, b: Color3, t: number): Color3
	return a:Lerp(b, math.clamp(t, 0, 1))
end

local function scaleColor(color: Color3, factor: number): Color3
	return Color3.new(math.clamp(color.R * factor, 0, 1), math.clamp(color.G * factor, 0, 1),
		math.clamp(color.B * factor, 0, 1))
end

local function plainPart(name: string, parent: Instance): Part
	local part = Instance.new("Part")
	part.Name = name
	part.Anchored = true
	part.CanCollide = false
	part.CanQuery = false
	part.CanTouch = false
	part.CastShadow = false
	part.Transparency = 1
	part.Size = Vector3.one
	part.Parent = parent
	return part
end

type Options = {
	picture: (key: string) -> Content?,
	glow: ((key: string) -> Content?)?, -- sun / moon: their black made see-through (Minecraft adds them onto the sky)
	assets: () -> any,
	shaderActive: () -> boolean,
}

function Sky.start(options: Options)
	local Character = require(ReplicatedStorage:WaitForChild("MinecraftCharacter")) :: any
	local camera = workspace.CurrentCamera
	local holder = Instance.new("Folder")
	holder.Name = "MinecraftSky"
	holder.Parent = workspace -- (made by this client: only here)

	-- region Lighting, Atmosphere, Sky
	local atmosphere = Lighting:FindFirstChildOfClass("Atmosphere")
	if not atmosphere then
		local made = Instance.new("Atmosphere")
		made.Name = "McAtmosphere"
		made.Parent = Lighting
		atmosphere = made
	end
	local sky = Lighting:FindFirstChildOfClass("Sky")
	if not sky then
		local made = Instance.new("Sky")
		made.Name = "McSky"
		made.Parent = Lighting
		sky = made
	end
	pcall(function()
		local s = sky :: Sky
		s.SunAngularSize = 0 -- (Minecraft's square sun and its moon are drawn below)
		s.MoonAngularSize = 0
		s.CelestialBodiesShown = true -- (the stars)
	end)
	local tint = Instance.new("ColorCorrectionEffect")
	tint.Name = "McUnderwater"
	tint.Enabled = false
	tint.Parent = Lighting
	-- endregion

	-- region sun + moon
	local function celestial(name: string): (Part, ImageLabel, BillboardGui)
		local anchor = plainPart(name, holder)
		local gui = Instance.new("BillboardGui")
		gui.Name = name
		gui.Adornee = anchor
		gui.AlwaysOnTop = false
		gui.LightInfluence = 0
		gui.MaxDistance = math.huge
		gui.ResetOnSpawn = false
		gui.Parent = anchor
		local label = Instance.new("ImageLabel")
		label.BackgroundTransparency = 1
		label.Size = UDim2.fromScale(1, 1)
		label.ResampleMode = Enum.ResamplerMode.Pixelated
		label.Parent = gui
		return anchor, label, gui
	end
	local sunAnchor, sunImage, sunGui = celestial("Sun")
	local moonAnchor, moonImage, moonGui = celestial("Moon")
	-- endregion

	-- region clouds
	local clouds = plainPart("Clouds", holder)
	clouds.Size = Vector3.new(CLOUD_SIZE, 0.2, CLOUD_SIZE)
	local cloudTextures = {}
	for _, face in ipairs({ Enum.NormalId.Top, Enum.NormalId.Bottom }) do
		local texture = Instance.new("Texture")
		texture.Face = face
		texture.StudsPerTileU = CLOUD_TILE_BLOCKS * BLOCK
		texture.StudsPerTileV = CLOUD_TILE_BLOCKS * BLOCK
		texture.Parent = clouds
		table.insert(cloudTextures, texture)
	end
	-- endregion

	-- region rain + snow: one part per block column around the camera
	local columns = {}
	for dx = -WEATHER_RADIUS, WEATHER_RADIUS do
		for dz = -WEATHER_RADIUS, WEATHER_RADIUS do
			if dx * dx + dz * dz <= WEATHER_RADIUS * WEATHER_RADIUS then
				local part = plainPart("Weather", holder)
				local textures = {}
				for _, face in ipairs({ Enum.NormalId.Front, Enum.NormalId.Back }) do
					local texture = Instance.new("Texture")
					texture.Face = face
					texture.StudsPerTileU = BLOCK
					texture.StudsPerTileV = 4 * BLOCK -- Minecraft: one picture is 1 x 4 blocks
					texture.Transparency = 1
					texture.Parent = part
					table.insert(textures, texture)
				end
				table.insert(columns, { dx = dx, dz = dz, part = part, textures = textures, phase = math.random(),
					speed = 3 + math.random(), drift = math.random(), ground = nil :: number?, key = nil :: string?,
					shown = false })
			end
		end
	end
	local groundParams = RaycastParams.new()
	groundParams.FilterType = Enum.RaycastFilterType.Include
	pcall(function()
		groundParams.RespectCanCollide = true
	end)
	local groundAt = 0
	-- endregion

	-- the values shown (they follow Minecraft's smoothly)
	local shown = {
		sun = attribute("McSunAngle", 0) :: number,
		moon = attribute("McMoonAngle", 180) :: number,
		skyLight = attribute("McSkyLight", 1) :: number,
		sky = attribute("McSkyColor", Color3.fromRGB(120, 167, 255)) :: Color3,
		fog = attribute("McFogColor", Color3.fromRGB(192, 216, 255)) :: Color3,
		cloud = attribute("McCloudColor", Color3.new(1, 1, 1)) :: Color3,
		sunrise = attribute("McSunriseColor", Color3.new(1, 0.8, 0.2)) :: Color3,
		sunriseAlpha = attribute("McSunriseAlpha", 0) :: number,
		rain = attribute("McRain", 0) :: number,
		stars = attribute("McStarBrightness", 0) :: number,
	}
	local started = os.clock()

	local function follow(current: number, wanted: number, blend: number, wrap: number?): number
		if wrap then
			local difference = (wanted - current + wrap / 2) % wrap - wrap / 2
			if math.abs(difference) > 30 then
				return wanted -- (/time set: jump there)
			end
			return current + difference * blend
		end
		return current + (wanted - current) * blend
	end

	RunService.RenderStepped:Connect(function(dt)
		camera = workspace.CurrentCamera
		if not camera then
			return
		end
		local assets = options.assets()
		local scale = if assets and assets.scale then assets.scale else BLOCK
		updateDimension(assets, camera.CFrame.Position.Y, scale)
		local blend = 1 - math.exp(-dt * SMOOTH)
		shown.sun = follow(shown.sun, dimAttribute("McSunAngle", 0), blend, 360)
		shown.moon = follow(shown.moon, dimAttribute("McMoonAngle", 180), blend, 360)
		shown.skyLight = follow(shown.skyLight, dimAttribute("McSkyLight", 1), blend)
		shown.sky = lerpColor(shown.sky, dimAttribute("McSkyColor", shown.sky), blend)
		shown.fog = lerpColor(shown.fog, dimAttribute("McFogColor", shown.fog), blend)
		shown.cloud = lerpColor(shown.cloud, dimAttribute("McCloudColor", shown.cloud), blend)
		shown.sunrise = lerpColor(shown.sunrise, dimAttribute("McSunriseColor", shown.sunrise), blend)
		shown.sunriseAlpha = follow(shown.sunriseAlpha, dimAttribute("McSunriseAlpha", 0), blend)
		shown.rain = follow(shown.rain, dimAttribute("McRain", 0), blend)
		shown.stars = follow(shown.stars, dimAttribute("McStarBrightness", 0), blend)

		-- region Lighting: the clock + Minecraft's light (unless a shader of the settings menu does the look)
		Lighting.ClockTime = Sky.clockTime(shown.sun)
		Lighting.GeographicLatitude = 0 -- (Minecraft's sun goes right over the head)
		local brightness = Sky.brightness(shown.skyLight)
		local daylight = math.clamp((shown.skyLight - 0.24) / 0.76, 0, 1) -- how much the sun itself shines
		local eye = camera.CFrame.Position
		local fluid = Character.fluidAt(eye)
		-- status effects (MinecraftPlayer keeps them in Sky.effects): night vision = everything lit like the day,
		-- blindness / darkness = black fog close around the eyes
		local effects = Sky.effects
		local nightVision = effects.night_vision ~= nil
		local blind = effects.blindness ~= nil or effects.darkness ~= nil
		if not options.shaderActive() then
			local skyLightColor = dimAttribute("McSkyLightColor", Color3.new(1, 1, 1)) :: Color3
			Lighting.Brightness = 2.4 * (if nightVision then 1 else daylight)
			Lighting.OutdoorAmbient = scaleColor(skyLightColor, (if nightVision then 1 else brightness) * 0.62)
			Lighting.Ambient = if nightVision then Color3.fromRGB(150, 150, 150) else Color3.fromRGB(16, 16, 20) -- (Minecraft: no sky light = dark, only block light)
			Lighting.ColorShift_Top = lerpColor(Color3.new(1, 1, 1), shown.sunrise, shown.sunriseAlpha * 0.6)
			Lighting.ColorShift_Bottom = Color3.new(0, 0, 0)
			Lighting.EnvironmentDiffuseScale = 0 -- (no reflections of the sky: Minecraft's blocks are plain)
			Lighting.EnvironmentSpecularScale = 0
			Lighting.GlobalShadows = true
			Lighting.ShadowSoftness = 0.35
			Lighting.ExposureCompensation = 0
			local a = atmosphere :: Atmosphere
			if blind then
				-- Minecraft: blindness = fog from 0 to 5 blocks, black
				a.Color = Color3.new(0, 0, 0)
				a.Decay = Color3.new(0, 0, 0)
				a.Density = 1
				a.Offset = 0
				a.Haze = 10
				a.Glare = 0
				tint.Enabled = true
				tint.TintColor = Color3.fromRGB(110, 110, 110)
				tint.Saturation = -0.3
			elseif fluid == "water" then
				-- Minecraft's water fog: its colour, 96 blocks far (darker at night)
				local water = lerpColor(dimAttribute("McWaterFogColor", Color3.fromRGB(5, 5, 51)),
					dimAttribute("McWaterColor", Color3.fromRGB(63, 118, 228)), 0.4)
				a.Color = scaleColor(water, 0.3 + 0.7 * brightness)
				a.Decay = a.Color
				a.Density = 0.55
				a.Offset = 0
				a.Haze = 0
				a.Glare = 0
				tint.Enabled = true
				tint.TintColor = Color3.fromRGB(150, 185, 255)
				tint.Saturation = -0.1
			elseif fluid == "lava" then
				a.Color = Color3.fromRGB(153, 25, 0) -- Minecraft: lava fog 0.6 / 0.1 / 0
				a.Decay = a.Color
				a.Density = 0.9
				a.Offset = 0
				a.Haze = 0
				a.Glare = 0
				tint.Enabled = true
				tint.TintColor = Color3.fromRGB(255, 170, 120)
				tint.Saturation = 0
			elseif current then
				-- the Nether / the End: no sun; the Nether's biome fog close around, the End dark
				local nether = currentKind ~= "end"
				local ambient = rgbOf(current.ambient, Color3.new())
				if ambient.R + ambient.G + ambient.B < 0.15 then
					ambient = if nether then Color3.fromRGB(95, 78, 72) else Color3.fromRGB(105, 100, 118)
				end
				Lighting.Brightness = 0
				Lighting.OutdoorAmbient = if nightVision then Color3.fromRGB(200, 200, 200) else ambient
				Lighting.Ambient = if nightVision then Color3.fromRGB(150, 150, 150) else scaleColor(ambient, 0.8)
				Lighting.GlobalShadows = false
				a.Color = shown.fog
				a.Decay = if nether then shown.fog else shown.sky
				a.Density = if nether then 0.62 else 0.4
				a.Offset = 0
				a.Haze = if nether then 2 else 0.5
				a.Glare = 0
				tint.Enabled = false
			else
				-- the horizon in Minecraft's fog colour, above it its sky colour; the sunrise glows into the haze
				a.Color = lerpColor(shown.fog, shown.sunrise, shown.sunriseAlpha * 0.5)
				a.Decay = shown.sky
				a.Density = 0.32
				a.Offset = 0.15
				a.Haze = 1.4
				a.Glare = shown.sunriseAlpha * 2
				tint.Enabled = false
			end
		end
		pcall(function()
			(sky :: Sky).StarCount = math.floor(3000 * math.clamp(shown.stars * 2, 0, 1) * (1 - shown.rain))
		end)
		-- endregion

		-- region sun + moon: where Roblox has them (the clock above), Minecraft's pictures
		local hidden = 1 - math.clamp(shown.rain, 0, 1) -- Minecraft: rain hides sun and moon
		if current and current.skybox ~= "overworld" then
			hidden = 0 -- (the Nether / the End have none)
		end
		local function place(anchor: Part, gui: BillboardGui, image: ImageLabel, direction: Vector3, size: number,
			key: string?)
			anchor.CFrame = CFrame.new(eye + direction * CELESTIAL_DISTANCE)
			local studs = size * CELESTIAL_DISTANCE * 2
			gui.Size = UDim2.fromScale(studs, studs)
			local glow: (string) -> Content? = options.glow or options.picture
			local content = if key then glow(key) else nil
			if content and image.ImageContent ~= content then
				image.ImageContent = content
			end
			image.ImageTransparency = if content then 1 - hidden else 1
		end
		local gui = assets and assets.gui or {}
		place(sunAnchor, sunGui, sunImage, Lighting:GetSunDirection(), SUN_SIZE, gui.sun)
		local phase = dimAttribute("McMoonPhase", "full_moon")
		place(moonAnchor, moonGui, moonImage, Lighting:GetMoonDirection(), MOON_SIZE, gui["moon_" .. tostring(phase)])
		-- endregion

		-- region clouds: at Minecraft's cloud height, drifting east, the picture fixed to the world
		local minY = if assets and assets.minY then assets.minY else -64
		local cloudY = dimAttribute("McCloudHeight", (192.33 - minY) * scale) :: number
		local tile = CLOUD_TILE_BLOCKS * scale
		local centre = Vector3.new(math.floor(eye.X / 64) * 64, cloudY, math.floor(eye.Z / 64) * 64)
		clouds.CFrame = CFrame.new(centre)
		local drift = (os.clock() - started) * CLOUD_SPEED * scale
		local cloudContent = if gui.clouds then options.picture(gui.clouds) else nil
		local cloudAlpha = (dimAttribute("McCloudAlpha", 0.8) :: number)
		for _, texture in ipairs(cloudTextures) do
			if cloudContent and texture.TextureContent ~= cloudContent then
				texture.TextureContent = cloudContent
			end
			texture.OffsetStudsU = -((centre.X - CLOUD_SIZE / 2 - drift) % tile)
			texture.OffsetStudsV = -((centre.Z - CLOUD_SIZE / 2) % tile)
			texture.Color3 = shown.cloud
			texture.Transparency = if cloudContent then 1 - cloudAlpha else 1
		end
		-- endregion

		-- region rain + snow
		local precipitation = dimAttribute("McPrecipitation", "none")
		local raining = shown.rain > 0.01 and precipitation ~= "none"
		local snow = precipitation == "snow"
		local weatherKey = if snow then gui.snow else gui.rain
		local weatherContent = if raining and weatherKey then options.picture(weatherKey) else nil
		local worldFolder = workspace:FindFirstChild("MinecraftWorld")
		local now = os.clock()
		local refreshGround = now - groundAt > GROUND_EVERY
		if refreshGround then
			groundAt = now
			groundParams.FilterDescendantsInstances = if worldFolder then { worldFolder } else {}
		end
		local baseX, baseZ = math.floor(eye.X / scale), math.floor(eye.Z / scale)
		for _, column in ipairs(columns) do
			local part = column.part
			if not weatherContent then
				if column.shown then
					column.shown = false
					for _, texture in ipairs(column.textures) do
						texture.Transparency = 1
					end
				end
				continue
			end
			local x, z = baseX + column.dx, baseZ + column.dz
			local key = x .. "," .. z
			if refreshGround or column.key ~= key then
				column.key = key
				local from = Vector3.new((x + 0.5) * scale, eye.Y + WEATHER_HEIGHT * scale, (z + 0.5) * scale)
				local hit = if worldFolder then workspace:Raycast(from, Vector3.new(0, -(WEATHER_HEIGHT * 2 + 60) * scale, 0),
					groundParams) else nil
				column.ground = if hit then hit.Position.Y else -math.huge
			end
			local bottom = math.max(column.ground or -math.huge, eye.Y - WEATHER_HEIGHT * scale)
			local top = eye.Y + WEATHER_HEIGHT * scale
			if bottom >= top - 0.1 then
				for _, texture in ipairs(column.textures) do
					texture.Transparency = 1
				end
				continue
			end
			local centreXZ = Vector3.new((x + 0.5) * scale, (bottom + top) / 2, (z + 0.5) * scale)
			part.Size = Vector3.new(scale, top - bottom, 0.05)
			local toward = Vector3.new(eye.X, centreXZ.Y, eye.Z)
			part.CFrame = if (toward - centreXZ).Magnitude > 0.01 then CFrame.lookAt(centreXZ, toward) else CFrame.new(centreXZ)
			-- Minecraft: rain falls 3-4 pictures (of 4 blocks) per 32 ticks, snow one picture per 512 ticks, drifting
			local time = now - started
			local fall = if snow then time / 25.6 + column.phase else (time / 1.6 * column.speed + column.phase)
			local distance2 = column.dx * column.dx + column.dz * column.dz
			local fade = 1 - distance2 / (WEATHER_RADIUS * WEATHER_RADIUS)
			local alpha = (fade * (if snow then 0.3 else 0.5) + 0.5) * math.clamp(shown.rain, 0, 1)
			for _, texture in ipairs(column.textures) do
				if texture.TextureContent ~= weatherContent then
					texture.TextureContent = weatherContent
				end
				texture.StudsPerTileU = scale
				texture.StudsPerTileV = 4 * scale
				-- A bigger OffsetStudsV moves the picture UP (Paddy's test: rain flew up with +fall). Picture point
				-- t = (v + offset) / tile, v = top - y  =>  offset = -top - fall: the picture hangs in the world (does not
				-- slide when the camera goes up / down) and falls DOWN
				texture.OffsetStudsV = (-top - fall * 4 * scale) % (4 * scale) -- (falling down)
				texture.OffsetStudsU = if snow then ((column.drift + time * 0.01 * column.drift) * scale) % scale else 0
				texture.Transparency = 1 - alpha
			end
			column.shown = true
		end
		-- endregion
	end)

	-- the player's own camera owns nothing here: when he leaves, everything goes with the client
	Players.LocalPlayer.AncestryChanged:Connect(function()
		if not Players.LocalPlayer.Parent then
			holder:Destroy()
		end
	end)
end

return Sky
