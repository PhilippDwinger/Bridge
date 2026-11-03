--!strict
--[[
	MinecraftImages - pixel work for the pictures from Minecraft (ModuleScript "MinecraftImages" in ReplicatedStorage)

	Pure functions on RGBA buffers (4 bytes per pixel, row by row, like EditableImage:WritePixelsBuffer wants them).
	No Roblox objects in here, so it also runs in the tests (Lune).

	    local big = Images.upscale(texture, 8)              -- 16x16 -> 128x128, every pixel a sharp 8x8 square
	    local icon = Images.blockIcon(top, left, right, 128) -- the block as a little 3D cube, like in the inventory
	    local icon = Images.modelIcon(boxes, 128)           -- a model (stairs, button, fence) the same way
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

--- Turned clockwise by 90 / 180 / 270 degrees.
function Images.turn(picture: Picture, degrees: number): Picture
	local quarter = (degrees // 90) % 4
	if quarter == 0 then
		return picture
	end
	local w, h = picture.w, picture.h
	local outW, outH = if quarter == 2 then w else h, if quarter == 2 then h else w
	local out = buffer.create(outW * outH * 4)
	for y = 0, h - 1 do
		for x = 0, w - 1 do
			local pixel = buffer.readu32(picture.pixels, (y * w + x) * 4)
			local nx, ny
			if quarter == 1 then
				nx, ny = h - 1 - y, x
			elseif quarter == 2 then
				nx, ny = w - 1 - x, h - 1 - y
			else
				nx, ny = y, w - 1 - x
			end
			buffer.writeu32(out, (ny * outW + nx) * 4, pixel)
		end
	end
	return { w = outW, h = outH, pixels = out }
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

--- A part of a picture (x, y, w, h in pixels; outside the picture = transparent) - e.g. one face out of a skin.
function Images.crop(picture: Picture, x: number, y: number, w: number, h: number): Picture
	local out = buffer.create(w * h * 4)
	local source = picture.pixels
	for row = 0, h - 1 do
		local sy = y + row
		if sy >= 0 and sy < picture.h then
			for column = 0, w - 1 do
				local sx = x + column
				if sx >= 0 and sx < picture.w then
					buffer.writeu32(out, (row * w + column) * 4, buffer.readu32(source, (sy * picture.w + sx) * 4))
				end
			end
		end
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
	top face full bright, left face (Minecraft: north) a bit darker, right face (east) darker still. size x size
	pixels, transparent around. Transparent pixels of a texture (glass, leaves) stay transparent. thickness < 1 = a
	thin block lying at the bottom (a closed trapdoor: 3/16), its sides show the whole side picture.

	Projection of the unit cube: top corner V0, x axis to the right-down (a, b), z axis to the left-down (-a, b),
	y axis up (0, -h). For every pixel the face and its texture position are found by solving that backwards.
]]
function Images.blockIcon(top: Picture, left: Picture, right: Picture, size: number, thickness: number?): Picture
	local out = buffer.create(size * size * 4) -- all 0 = transparent
	local edge = size * 0.6
	local a = edge * 0.70710678 -- cos 45
	local b = edge * 0.35355339 -- sin 45 * sin 30
	local full = edge * 0.8660254 -- cos 30
	local h = full * (thickness or 1) -- a thin block (trapdoor: 3/16) lies at the bottom of the cube's place
	local height = 2 * b + full
	local cx = size / 2
	local topY = (size - height) / 2 + (full - h)
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
					sample(left, s, t, 0.8, out, offset)
				end
			else
				-- right face (the x = 1 side): q = (a, b) + s*(-a, b) + t*(0, h)
				local s = (a - qx) / a
				local t = (qy - b - s * b) / h
				if s >= 0 and s <= 1 and t >= 0 and t <= 1 then
					sample(right, 1 - s, t, 0.6, out, offset)
				end
			end
		end
	end
	return { w = size, h = size, pixels = out }
end

export type IconBox = { from: { number }, to: { number }, faces: { [string]: Picture? } }

--[[
	A model as an item icon (stairs, slabs, fences, buttons, trapdoors): its boxes (in pixels 0..16, along the axes)
	seen like blockIcon sees a cube - from above, the south side on the left, the east side on the right. For every
	pixel the ray into the picture finds the nearest box face; that face's picture is sampled in Minecraft's face
	orientation (up: east right / south down; south: east right; east: north right; sides upright).
]]
function Images.modelIcon(boxes: { IconBox }, size: number): Picture
	local out = buffer.create(size * size * 4)
	local edge = size * 0.6
	local a = edge * 0.70710678
	local b = edge * 0.35355339
	local full = edge * 0.8660254
	local cx = size / 2
	local originY = (size - (2 * b + full)) / 2 + full -- the screen point of the block's corner (0, 0, 0)
	-- the direction into the picture: screen(D) = 0
	local dx, dy, dz = -1, -2 * b / full, -1
	for py = 0, size - 1 do
		for px = 0, size - 1 do
			-- a point on the ray at height 0: screen = (cx, originY) + x (a, b) + z (-a, b)
			local qx, qy = px + 0.5 - cx, py + 0.5 - originY
			local x0 = (qx / a + qy / b) / 2
			local z0 = (qy / b - qx / a) / 2
			-- start far on the viewer's side, go along D
			local sx, sy, sz = x0 - 3 * dx, -3 * dy, z0 - 3 * dz
			local best, bestFace, bestBox = math.huge, nil, nil
			for _, box in ipairs(boxes) do
				local lo = { box.from[1] / 16, box.from[2] / 16, box.from[3] / 16 }
				local hi = { box.to[1] / 16, box.to[2] / 16, box.to[3] / 16 }
				local tmin, tmax, face = -math.huge, math.huge, nil
				local origin = { sx, sy, sz }
				local direction = { dx, dy, dz }
				local names = { "east", "up", "south" } -- the face you enter through, per axis (rays go towards -x, -y, -z)
				local miss = false
				for axis = 1, 3 do
					local o, d = origin[axis], direction[axis]
					local t1, t2 = (hi[axis] - o) / d, (lo[axis] - o) / d -- d < 0: hi first
					if t1 > tmin then
						tmin = t1
						face = names[axis]
					end
					if t2 < tmax then
						tmax = t2
					end
					if tmin > tmax then
						miss = true
						break
					end
				end
				if not miss and face and tmin < best then
					best, bestFace, bestBox = tmin, face, box
				end
			end
			if bestBox and bestFace then
				local picture = bestBox.faces[bestFace]
				if picture then
					local hx, hy, hz = sx + best * dx, sy + best * dy, sz + best * dz
					local from, to = bestBox.from, bestBox.to
					local function fraction(value: number, low: number, high: number): number
						return if high - low > 1e-6 then math.clamp((value * 16 - low) / (high - low), 0, 0.9999) else 0
					end
					local u, v, shade
					if bestFace == "up" then
						u, v, shade = fraction(hx, from[1], to[1]), fraction(hz, from[3], to[3]), 1
					elseif bestFace == "south" then
						u, v, shade = fraction(hx, from[1], to[1]), 1 - fraction(hy, from[2], to[2]), 0.8
					else
						u, v, shade = 1 - fraction(hz, from[3], to[3]), 1 - fraction(hy, from[2], to[2]), 0.6
					end
					sample(picture, u, math.clamp(v, 0, 0.9999), shade, out, (py * size + px) * 4)
				end
			end
		end
	end
	return { w = size, h = size, pixels = out }
end

return Images
