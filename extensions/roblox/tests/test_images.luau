--[[
	Unit test of MinecraftImages (the pixel work for textures and item icons): lune run test_images.luau
]]
local process = require("@lune/process")
local Images = require("../examples/MinecraftWorld/MinecraftImages")
local results = { ok = 0, fail = 0 }

local function check(name, condition, info)
	if condition then
		results.ok += 1
		print("  OK    " .. name)
	else
		results.fail += 1
		print("  FAIL  " .. name .. "  " .. tostring(info or ""))
	end
end

local function pixel(picture, x, y)
	local i = (y * picture.w + x) * 4
	local p = picture.pixels
	return buffer.readu8(p, i), buffer.readu8(p, i + 1), buffer.readu8(p, i + 2), buffer.readu8(p, i + 3)
end

-- a 2x2 picture: red, green / blue, white (half transparent)
local tiny = { w = 2, h = 2, pixels = buffer.create(16) }
local colors = { { 255, 0, 0, 255 }, { 0, 255, 0, 255 }, { 0, 0, 255, 255 }, { 255, 255, 255, 128 } }
for i, c in ipairs(colors) do
	for k = 1, 4 do
		buffer.writeu8(tiny.pixels, (i - 1) * 4 + k - 1, c[k])
	end
end

local big = Images.upscale(tiny, 3)
local r1, g1, b1, a1 = pixel(big, 2, 2)
local r2, g2, b2, a2 = pixel(big, 3, 0)
local r3, g3, b3, a3 = pixel(big, 5, 5)
check("upscale 2x2 -> 6x6: every pixel a sharp 3x3 square", big.w == 6 and big.h == 6 and buffer.len(big.pixels) == 144
	and r1 == 255 and g1 == 0 and a1 == 255 and r2 == 0 and g2 == 255 and b2 == 0 and a2 == 255
	and r3 == 255 and g3 == 255 and b3 == 255 and a3 == 128)

local solid = Images.solid(4, 3, 10, 20, 30)
local sr, sg, sb, sa = pixel(solid, 3, 2)
check("solid: one colour everywhere, opaque", buffer.len(solid.pixels) == 48 and sr == 10 and sg == 20 and sb == 30 and sa == 255)

-- block icon from a plain top (200, 100, 50) and side (100, 200, 50)
local top = Images.solid(16, 16, 200, 100, 50)
local side = Images.solid(16, 16, 100, 200, 50)
local icon = Images.blockIcon(top, side, side, 64)
local _, _, _, cornerAlpha = pixel(icon, 0, 0)
local _, _, _, bottomAlpha = pixel(icon, 0, 63)
local tr, tg, tb, ta = pixel(icon, 32, 14) -- middle of the top face
local lr, lg, lb, la = pixel(icon, 18, 40) -- left face
local rr, rg, rb, ra = pixel(icon, 46, 40) -- right face
check("block icon: transparent around the cube", cornerAlpha == 0 and bottomAlpha == 0)
check("block icon: top face = top texture, full bright", tr == 200 and tg == 100 and tb == 50 and ta == 255, tr .. "," .. tg)
check("block icon: left face = side texture * 0.8", lr == 80 and lg == 160 and lb == 40 and la == 255, lr .. "," .. lg)
check("block icon: right face = side texture * 0.6", rr == 60 and rg == 120 and rb == 30 and ra == 255, rr .. "," .. rg)

print(string.format("\n%d ok, %d failed", results.ok, results.fail))
process.exit(if results.fail > 0 then 1 else 0)
