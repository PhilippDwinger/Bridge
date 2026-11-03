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

-- crop: one face out of a skin (here a 4x3 picture, the 2x2 part at 1,1; outside = transparent)
local sheet = Images.solid(4, 3, 0, 0, 0)
for y = 0, 2 do
	for x = 0, 3 do
		buffer.writeu8(sheet.pixels, (y * 4 + x) * 4, x * 10 + y)
	end
end
local face = Images.crop(sheet, 1, 1, 2, 2)
local edge = Images.crop(sheet, 3, 2, 2, 2)
local c00 = pixel(face, 0, 0)
local c11 = pixel(face, 1, 1)
local _, _, _, outside = pixel(edge, 1, 1)
check("crop: the part of the picture (a face of a skin), outside the picture transparent",
	face.w == 2 and face.h == 2 and c00 == 11 and c11 == 22 and pixel(edge, 0, 0) == 32 and outside == 0)

-- turn: clockwise like Minecraft's face rotation (a 2 x 1 picture -> 1 x 2, the left pixel on top)
local strip = Images.solid(2, 1, 0, 0, 0)
buffer.writeu8(strip.pixels, 0, 1)
buffer.writeu8(strip.pixels, 4, 2)
local turned = Images.turn(strip, 90)
local back = Images.turn(Images.turn(turned, 180), 90)
check("turn: 90 degrees clockwise (2 x 1 -> 1 x 2, left -> top), 4 x 90 = the same picture",
	turned.w == 1 and turned.h == 2 and pixel(turned, 0, 0) == 1 and pixel(turned, 0, 1) == 2
	and back.w == 2 and pixel(back, 0, 0) == 1 and pixel(back, 1, 0) == 2)

-- model icon: a slab (bottom half): the top face lower than a full cube's, the upper part transparent
local slab = Images.modelIcon({ { from = { 0, 0, 0 }, to = { 16, 8, 16 }, faces = { up = top, south = side, east = side } } }, 64)
local full = Images.modelIcon({ { from = { 0, 0, 0 }, to = { 16, 16, 16 }, faces = { up = top, south = side, east = side } } }, 64)
local fr, fg, _, fa = pixel(full, 32, 14)
local _, _, _, sa = pixel(slab, 32, 14)
local sr, sg = pixel(slab, 32, 28)
local lr2, lg2 = pixel(full, 18, 40)
local rr2, rg2 = pixel(full, 46, 40)
check("model icon: a full box looks like the block icon (top bright, south side * 0.8 left, east * 0.6 right)",
	fr == 200 and fg == 100 and fa == 255 and lr2 == 80 and lg2 == 160 and rr2 == 60 and rg2 == 120, fr .. "," .. lr2 .. "," .. rr2)
check("model icon: a slab - nothing where a cube's top would be, its own top lower down", sa == 0 and sr == 200 and sg == 100,
	sa .. "," .. sr)

-- sun / moon (Minecraft adds them onto the sky): black -> see-through, dark -> faint, the colour kept
local sky = { w = 3, h = 1, pixels = buffer.create(12) }
for i, c in ipairs({ { 0, 0, 0, 255 }, { 255, 255, 128, 255 }, { 40, 20, 10, 255 } }) do
	for k = 1, 4 do
		buffer.writeu8(sky.pixels, (i - 1) * 4 + k - 1, c[k])
	end
end
local glow = Images.additive(sky)
local _, _, _, ba = pixel(glow, 0, 0)
local yr, yg, yb, ya = pixel(glow, 1, 0)
local dr, dg, db, da = pixel(glow, 2, 0)
check("additive (sun, moon): black around them see-through (no box), bright opaque, dark faint in its own colour",
	ba == 0 and yr == 255 and yg == 255 and yb == 128 and ya == 255 and da == 40 and dr == 255 and dg == 128 and db == 64,
	string.format("%d | %d %d %d %d | %d %d %d %d", ba, yr, yg, yb, ya, dr, dg, db, da))

print(string.format("\n%d ok, %d failed", results.ok, results.fail))
process.exit(if results.fail > 0 then 1 else 0)
