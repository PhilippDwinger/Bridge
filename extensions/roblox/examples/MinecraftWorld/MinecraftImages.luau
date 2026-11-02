--!strict
--[[
	MinecraftImages - pixel work for the pictures from Minecraft (ModuleScript "MinecraftImages" in ReplicatedStorage)

	Pure functions on RGBA buffers (4 bytes per pixel, row by row, like EditableImage:WritePixelsBuffer wants them).
	No Roblox objects in here, so it also runs in the tests (Lune).

	    local big = Images.upscale(texture, 8)              -- 16x16 -> 128x128, every pixel a sharp 8x8 square
	    local icon = Images.blockIcon(top, side, 128)       -- the block as a little 3D cube, like in the inventory
]]
export type Picture = { w: number, h: number, pixels: buffer }

local Images = {}

--- Every pixel becomes a factor x factor square (sharp edges even where Roblox smooths textures).
function Images.upscale(picture: Picture, factor: number): Picture
	local w, h = picture.w * factor, picture.h * factor
	local out = buffer.create(w * h * 4)
	local source = picture.pixels
	for y = 0, h - 1 do
		local sourceRow = (y // factor) * picture.w
		local row = y * w
		for x = 0, w - 1 do
			buffer.writeu32(out, (row + x) * 4, buffer.readu32(source, (sourceRow + x // factor) * 4))
		end
	end
	return { w = w, h = h, pixels = out }
end

--- One colour everywhere (for blocks / items without a picture).
function Images.solid(w: number, h: number, r: number, g: number, b: number, a: number?): Picture
	local out = buffer.create(w * h * 4)
	for i = 0, w * h - 1 do
		buffer.writeu8(out, i * 4, r)
		buffer.writeu8(out, i * 4 + 1, g)
		buffer.writeu8(out, i * 4 + 2, b)
		buffer.writeu8(out, i * 4 + 3, a or 255)
	end
	return { w = w, h = h, pixels = out }
end

local function sample(picture: Picture, u: number, v: number, shade: number, out: buffer, offset: number)
	local x = math.clamp(math.floor(u * picture.w), 0, picture.w - 1)
	local y = math.clamp(math.floor(v * picture.h), 0, picture.h - 1)
	local index = (y * picture.w + x) * 4
	local source = picture.pixels
	buffer.writeu8(out, offset, math.floor(buffer.readu8(source, index) * shade + 0.5))
	buffer.writeu8(out, offset + 1, math.floor(buffer.readu8(source, index + 1) * shade + 0.5))
	buffer.writeu8(out, offset + 2, math.floor(buffer.readu8(source, index + 2) * shade + 0.5))
	buffer.writeu8(out, offset + 3, buffer.readu8(source, index + 3))
end

--[[
	A block as an item icon: the cube seen from above at an angle (like Minecraft draws blocks in the inventory) -
	top face full bright, left face a bit darker, right face darker still. size x size pixels, transparent around.

	Projection of the unit cube: top corner V0, x axis to the right-down (a, b), z axis to the left-down (-a, b),
	y axis up (0, -h). For every pixel the face and its texture position are found by solving that backwards.
]]
function Images.blockIcon(top: Picture, side: Picture, size: number): Picture
	local out = buffer.create(size * size * 4) -- all 0 = transparent
	local edge = size * 0.6
	local a = edge * 0.70710678 -- cos 45
	local b = edge * 0.35355339 -- sin 45 * sin 30
	local h = edge * 0.8660254 -- cos 30
	local height = 2 * b + h
	local cx = size / 2
	local topY = (size - height) / 2
	for py = 0, size - 1 do
		for px = 0, size - 1 do
			local qx, qy = px + 0.5 - cx, py + 0.5 - topY
			local offset = (py * size + px) * 4
			-- top face: q = u*(a, b) + v*(-a, b)  ->  u = (qx/a + qy/b) / 2, v = (qy/b - qx/a) / 2
			local u = (qx / a + qy / b) / 2
			local v = (qy / b - qx / a) / 2
			if u >= 0 and u <= 1 and v >= 0 and v <= 1 then
				sample(top, u, v, 1, out, offset)
			elseif qx < 0 then
				-- left face (the z = 1 side): q = (-a, b) + s*(a, b) + t*(0, h)
				local s = (qx + a) / a
				local t = (qy - b - s * b) / h
				if s >= 0 and s <= 1 and t >= 0 and t <= 1 then
					sample(side, s, t, 0.8, out, offset)
				end
			else
				-- right face (the x = 1 side): q = (a, b) + s*(-a, b) + t*(0, h)
				local s = (a - qx) / a
				local t = (qy - b - s * b) / h
				if s >= 0 and s <= 1 and t >= 0 and t <= 1 then
					sample(side, 1 - s, t, 0.6, out, offset)
				end
			end
		end
	end
	return { w = size, h = size, pixels = out }
end

return Images
