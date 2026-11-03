--!strict
--[[
	MinecraftShaders - "shaders" like Minecraft shader packs (ModuleScript "MinecraftShaders" in ReplicatedStorage)

	Only the look changes, never the game: light, colours, bloom, sun rays, haze, clouds - nothing that moves, collides
	or decides anything. Only on this client (the effects are made by the LocalScript, Roblox does not send them to
	anybody, Bridge never sees them).

	    Shaders.apply("soft")   -- "off" (the game as it is), "soft", "vivid"
	    Shaders.LIST            -- {id, name, description} for the settings menu
]]
local Lighting = game:GetService("Lighting")

local Shaders = {}

Shaders.LIST = {
	{ id = "off", name = "Aus", description = "Das Spiel wie es ist" },
	{ id = "soft", name = "Sanft", description = "Warmes Licht, weiche Schatten, leichter Dunst, Wolken" },
	{ id = "vivid", name = "Kräftig", description = "Satte Farben, Leuchten, Sonnenstrahlen, goldener Dunst" },
}

type Look = {
	lighting: { [string]: any },
	atmosphere: { [string]: any }?,
	bloom: { [string]: any }?,
	color: { [string]: any }?,
	sunRays: { [string]: any }?,
	depth: { [string]: any }?,
	clouds: { [string]: any }?,
}

local LOOKS: { [string]: Look } = {
	soft = { -- like Complementary: calm and warm
		lighting = { GlobalShadows = true, ShadowSoftness = 0.25, Brightness = 2.6, ExposureCompensation = 0.1,
			EnvironmentDiffuseScale = 1, EnvironmentSpecularScale = 0.6, Ambient = Color3.fromRGB(50, 52, 62),
			OutdoorAmbient = Color3.fromRGB(128, 128, 140), ColorShift_Top = Color3.fromRGB(255, 244, 226),
			ColorShift_Bottom = Color3.fromRGB(70, 80, 110) },
		atmosphere = { Density = 0.3, Offset = 0.2, Color = Color3.fromRGB(205, 222, 250),
			Decay = Color3.fromRGB(112, 122, 140), Glare = 0.35, Haze = 1.2 },
		bloom = { Intensity = 0.35, Size = 28, Threshold = 1.3 },
		color = { Brightness = 0.02, Contrast = 0.08, Saturation = 0.14, TintColor = Color3.fromRGB(255, 249, 240) },
		sunRays = { Intensity = 0.05, Spread = 0.55 },
		clouds = { Cover = 0.5, Density = 0.55, Color = Color3.fromRGB(255, 255, 255) },
	},
	vivid = { -- like BSL: rich colours, glow, golden air
		lighting = { GlobalShadows = true, ShadowSoftness = 0.15, Brightness = 3.2, ExposureCompensation = 0.2,
			EnvironmentDiffuseScale = 1, EnvironmentSpecularScale = 1, Ambient = Color3.fromRGB(40, 36, 52),
			OutdoorAmbient = Color3.fromRGB(120, 110, 128), ColorShift_Top = Color3.fromRGB(255, 222, 180),
			ColorShift_Bottom = Color3.fromRGB(60, 70, 120) },
		atmosphere = { Density = 0.36, Offset = 0.15, Color = Color3.fromRGB(255, 220, 178),
			Decay = Color3.fromRGB(110, 80, 60), Glare = 0.9, Haze = 2.0 },
		bloom = { Intensity = 0.8, Size = 40, Threshold = 1.0 },
		color = { Brightness = 0.03, Contrast = 0.18, Saturation = 0.35, TintColor = Color3.fromRGB(255, 242, 228) },
		sunRays = { Intensity = 0.14, Spread = 0.8 },
		depth = { FarIntensity = 0.22, FocusDistance = 80, InFocusRadius = 60, NearIntensity = 0 },
		clouds = { Cover = 0.62, Density = 0.7, Color = Color3.fromRGB(255, 246, 236) },
	},
}

local PREFIX = "McShader"
local original: { [string]: any }? = nil -- Lighting as the game had it
local originalAtmosphere: { [string]: any }? = nil
local disabled: { Instance } = {} -- the game's own effects, switched off while a shader runs
local current = "off"

local LIGHTING_KEYS = { "GlobalShadows", "ShadowSoftness", "Brightness", "ExposureCompensation",
	"EnvironmentDiffuseScale", "EnvironmentSpecularScale", "Ambient", "OutdoorAmbient", "ColorShift_Top",
	"ColorShift_Bottom" }
local ATMOSPHERE_KEYS = { "Density", "Offset", "Color", "Decay", "Glare", "Haze" }

local function set(target: Instance, values: { [string]: any })
	for key, value in pairs(values) do
		pcall(function()
			(target :: any)[key] = value
		end)
	end
end

local function remember(target: Instance, keys: { string }): { [string]: any }
	local values = {}
	for _, key in ipairs(keys) do
		pcall(function()
			values[key] = (target :: any)[key]
		end)
	end
	return values
end

local function effect(className: string, parent: Instance, values: { [string]: any }?)
	local name = PREFIX .. className
	local item = parent:FindFirstChild(name)
	if not values then
		if item then
			item:Destroy()
		end
		return
	end
	local target: Instance = item or Instance.new(className)
	if not item then
		target.Name = name
		target.Parent = parent
	end
	set(target, values)
end

--- "off" | "soft" | "vivid" - unknown ids are "off".
function Shaders.apply(id: string)
	local look = LOOKS[id]
	if original == nil then
		original = remember(Lighting, LIGHTING_KEYS)
	end
	local atmosphere = Lighting:FindFirstChildOfClass("Atmosphere")
	if atmosphere and originalAtmosphere == nil and not string.find(atmosphere.Name, PREFIX, 1, true) then
		originalAtmosphere = remember(atmosphere, ATMOSPHERE_KEYS)
	end
	-- back to the game's own look first
	set(Lighting, original :: { [string]: any })
	for _, item in ipairs(disabled) do
		pcall(function()
			(item :: any).Enabled = true
		end)
	end
	table.clear(disabled)
	if atmosphere and originalAtmosphere then
		set(atmosphere, originalAtmosphere)
	end
	local terrain = workspace:FindFirstChildOfClass("Terrain")
	if not look then
		for _, className in ipairs({ "BloomEffect", "ColorCorrectionEffect", "SunRaysEffect", "DepthOfFieldEffect", "Atmosphere" }) do
			effect(className, Lighting, nil)
		end
		if terrain then
			effect("Clouds", terrain, nil)
		end
		current = "off"
		return
	end
	-- the game's own post effects step aside (they would add up with ours)
	for _, item in ipairs(Lighting:GetChildren()) do
		if item:IsA("PostEffect") and not string.find(item.Name, PREFIX, 1, true) and item.Enabled then
			item.Enabled = false
			table.insert(disabled, item)
		end
	end
	set(Lighting, look.lighting)
	if look.atmosphere then
		if atmosphere and not string.find(atmosphere.Name, PREFIX, 1, true) then
			set(atmosphere, look.atmosphere)
		else
			effect("Atmosphere", Lighting, look.atmosphere)
		end
	end
	effect("BloomEffect", Lighting, look.bloom)
	effect("ColorCorrectionEffect", Lighting, look.color)
	effect("SunRaysEffect", Lighting, look.sunRays)
	effect("DepthOfFieldEffect", Lighting, look.depth)
	if terrain then
		effect("Clouds", terrain, look.clouds)
	end
	current = id
end

function Shaders.current(): string
	return current
end

return Shaders
