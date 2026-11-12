--!strict
--[[
	Bridge 4 – Luau crypto (docs/10 §2.5, ADR 0021, risk R1).

	Roblox has no crypto primitives. This module is a line-by-line port of TweetNaCl (public domain; the C reference
	and tweetnacl-js, audited by Cure53 in 2017) for X25519, Ed25519 and Poly1305, plus SHA-256, SHA-512, HMAC,
	HKDF (RFC 5869) and ChaCha20 (RFC 8439) following the RFCs closely. Field elements are 16 limbs of 16 bits in Luau
	numbers (doubles), exactly like tweetnacl-js. Checked only against test vectors (RFC 8439, RFC 7748, RFC 8032,
	FIPS 180-4, RFC 5869) and the Bridge vectors - no independent review. No timing guarantees (interpreter).

	Bytes are Luau strings everywhere at the interface; internal arrays are 0-based like the C original.
]]

local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local lshift, rshift, lrotate, rrotate = bit32.lshift, bit32.rshift, bit32.lrotate, bit32.rrotate
local floor = math.floor
local TWO32 = 4294967296

local Crypto = {}

-- ---------------------------------------------------------------------------------------------------------------
-- helpers

local function toArray(s: string, n: number?): { number }
	local len = n or #s
	local out = table.create(len, 0)
	for i = 1, #s do
		out[i - 1] = string.byte(s, i)
	end
	for i = #s, len - 1 do
		out[i] = 0
	end
	return out
end

local function toString(a: { number }, n: number, offset: number?): string
	local o = offset or 0
	local b = buffer.create(n)
	for i = 0, n - 1 do
		buffer.writeu8(b, i, a[o + i])
	end
	return buffer.tostring(b)
end

Crypto.toArray = toArray
Crypto.toString = toString

local K256 = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
local H256 = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
local K512 = {0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, 0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5, 0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df, 0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8, 0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec, 0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b, 0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817}
local H512 = {0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179}

-- ---------------------------------------------------------------------------------------------------------------
-- SHA-256 (FIPS 180-4)

function Crypto.sha256(msg: string): string
	local len = #msg
	local padded = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. string.pack(">I4I4", floor(len / 536870912), (len * 8) % TWO32)
	local h = table.clone(H256)
	local w = table.create(64, 0)
	for chunk = 1, #padded, 64 do
		for i = 1, 16 do
			w[i] = string.unpack(">I4", padded, chunk + (i - 1) * 4)
		end
		for i = 17, 64 do
			local x, y = w[i - 15], w[i - 2]
			local s0 = bxor(rrotate(x, 7), rrotate(x, 18), rshift(x, 3))
			local s1 = bxor(rrotate(y, 17), rrotate(y, 19), rshift(y, 10))
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % TWO32
		end
		local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
		for i = 1, 64 do
			local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
			local ch = bxor(band(e, f), band(bnot(e), g))
			local t1 = (hh + S1 + ch + K256[i] + w[i]) % TWO32
			local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
			local maj = bxor(band(a, b), band(a, c), band(b, c))
			local t2 = (S0 + maj) % TWO32
			hh, g, f, e, d, c, b, a = g, f, e, (d + t1) % TWO32, c, b, a, (t1 + t2) % TWO32
		end
		h[1] = (h[1] + a) % TWO32
		h[2] = (h[2] + b) % TWO32
		h[3] = (h[3] + c) % TWO32
		h[4] = (h[4] + d) % TWO32
		h[5] = (h[5] + e) % TWO32
		h[6] = (h[6] + f) % TWO32
		h[7] = (h[7] + g) % TWO32
		h[8] = (h[8] + hh) % TWO32
	end
	return string.pack(">I4I4I4I4I4I4I4I4", h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8])
end

-- ---------------------------------------------------------------------------------------------------------------
-- SHA-512 (FIPS 180-4) on pairs of 32-bit halves

local function rotr64(h: number, l: number, n: number): (number, number)
	if n < 32 then
		return bor(rshift(h, n), lshift(l, 32 - n)), bor(rshift(l, n), lshift(h, 32 - n))
	elseif n == 32 then
		return l, h
	else
		n -= 32
		return bor(rshift(l, n), lshift(h, 32 - n)), bor(rshift(h, n), lshift(l, 32 - n))
	end
end

local function shr64(h: number, l: number, n: number): (number, number)
	return rshift(h, n), bor(rshift(l, n), lshift(h, 32 - n))
end

function Crypto.sha512(msg: string): string
	local len = #msg
	local padded = msg
		.. "\128"
		.. string.rep("\0", (111 - len) % 128)
		.. string.rep("\0", 8)
		.. string.pack(">I4I4", floor(len / 536870912), (len * 8) % TWO32)
	local h = table.clone(H512)
	local wh, wl = table.create(80, 0), table.create(80, 0)
	for chunk = 1, #padded, 128 do
		for i = 1, 16 do
			wh[i], wl[i] = string.unpack(">I4I4", padded, chunk + (i - 1) * 8)
		end
		for i = 17, 80 do
			local ah, al = rotr64(wh[i - 15], wl[i - 15], 1)
			local bh, bl = rotr64(wh[i - 15], wl[i - 15], 8)
			local ch, cl = shr64(wh[i - 15], wl[i - 15], 7)
			local s0h, s0l = bxor(ah, bh, ch), bxor(al, bl, cl)
			ah, al = rotr64(wh[i - 2], wl[i - 2], 19)
			bh, bl = rotr64(wh[i - 2], wl[i - 2], 61)
			ch, cl = shr64(wh[i - 2], wl[i - 2], 6)
			local s1h, s1l = bxor(ah, bh, ch), bxor(al, bl, cl)
			local lo = wl[i - 16] + s0l + wl[i - 7] + s1l
			wl[i] = lo % TWO32
			wh[i] = (wh[i - 16] + s0h + wh[i - 7] + s1h + floor(lo / TWO32)) % TWO32
		end
		local a_h, a_l, b_h, b_l, c_h, c_l, d_h, d_l = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
		local e_h, e_l, f_h, f_l, g_h, g_l, h_h, h_l = h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16]
		for i = 1, 80 do
			local r1h, r1l = rotr64(e_h, e_l, 14)
			local r2h, r2l = rotr64(e_h, e_l, 18)
			local r3h, r3l = rotr64(e_h, e_l, 41)
			local S1h, S1l = bxor(r1h, r2h, r3h), bxor(r1l, r2l, r3l)
			local chh = bxor(band(e_h, f_h), band(bnot(e_h), g_h))
			local chl = bxor(band(e_l, f_l), band(bnot(e_l), g_l))
			local t1l = h_l + S1l + chl + K512[2 * i] + wl[i]
			local t1h = (h_h + S1h + chh + K512[2 * i - 1] + wh[i] + floor(t1l / TWO32)) % TWO32
			t1l %= TWO32
			r1h, r1l = rotr64(a_h, a_l, 28)
			r2h, r2l = rotr64(a_h, a_l, 34)
			r3h, r3l = rotr64(a_h, a_l, 39)
			local S0h, S0l = bxor(r1h, r2h, r3h), bxor(r1l, r2l, r3l)
			local majh = bxor(band(a_h, b_h), band(a_h, c_h), band(b_h, c_h))
			local majl = bxor(band(a_l, b_l), band(a_l, c_l), band(b_l, c_l))
			local t2l = S0l + majl
			local t2h = (S0h + majh + floor(t2l / TWO32)) % TWO32
			t2l %= TWO32
			h_h, h_l, g_h, g_l, f_h, f_l = g_h, g_l, f_h, f_l, e_h, e_l
			local el = d_l + t1l
			e_h, e_l = (d_h + t1h + floor(el / TWO32)) % TWO32, el % TWO32
			d_h, d_l, c_h, c_l, b_h, b_l = c_h, c_l, b_h, b_l, a_h, a_l
			local al = t1l + t2l
			a_h, a_l = (t1h + t2h + floor(al / TWO32)) % TWO32, al % TWO32
		end
		local values = { a_h, a_l, b_h, b_l, c_h, c_l, d_h, d_l, e_h, e_l, f_h, f_l, g_h, g_l, h_h, h_l }
		for i = 1, 16, 2 do
			local lo = h[i + 1] + values[i + 1]
			h[i] = (h[i] + values[i] + floor(lo / TWO32)) % TWO32
			h[i + 1] = lo % TWO32
		end
	end
	local out = table.create(16)
	for i = 1, 16 do
		out[i] = string.pack(">I4", h[i])
	end
	return table.concat(out)
end

-- ---------------------------------------------------------------------------------------------------------------
-- HMAC-SHA256, HKDF-SHA256 (RFC 2104, RFC 5869)

function Crypto.hmacSha256(key: string, msg: string): string
	if #key > 64 then
		key = Crypto.sha256(key)
	end
	key ..= string.rep("\0", 64 - #key)
	local ipad, opad = table.create(64), table.create(64)
	for i = 1, 64 do
		local k = string.byte(key, i)
		ipad[i] = string.char(bxor(k, 0x36))
		opad[i] = string.char(bxor(k, 0x5c))
	end
	return Crypto.sha256(table.concat(opad) .. Crypto.sha256(table.concat(ipad) .. msg))
end

--- HKDF-SHA256 to 32 bytes.
function Crypto.hkdf32(ikm: string, salt: string, info: string): string
	local prk = Crypto.hmacSha256(salt, ikm)
	return Crypto.hmacSha256(prk, info .. "\1")
end

-- ---------------------------------------------------------------------------------------------------------------
-- ChaCha20 (RFC 8439 §2.3, §2.4)

local function quarter(s: { number }, a: number, b: number, c: number, d: number)
	s[a] = (s[a] + s[b]) % TWO32
	s[d] = lrotate(bxor(s[d], s[a]), 16)
	s[c] = (s[c] + s[d]) % TWO32
	s[b] = lrotate(bxor(s[b], s[c]), 12)
	s[a] = (s[a] + s[b]) % TWO32
	s[d] = lrotate(bxor(s[d], s[a]), 8)
	s[c] = (s[c] + s[d]) % TWO32
	s[b] = lrotate(bxor(s[b], s[c]), 7)
end

local function chachaBlock(key: string, counter: number, nonce: string): string
	local state = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }
	for i = 0, 7 do
		state[5 + i] = string.unpack("<I4", key, 1 + 4 * i)
	end
	state[13] = counter
	for i = 0, 2 do
		state[14 + i] = string.unpack("<I4", nonce, 1 + 4 * i)
	end
	local working = table.clone(state)
	for _ = 1, 10 do
		quarter(working, 1, 5, 9, 13)
		quarter(working, 2, 6, 10, 14)
		quarter(working, 3, 7, 11, 15)
		quarter(working, 4, 8, 12, 16)
		quarter(working, 1, 6, 11, 16)
		quarter(working, 2, 7, 12, 13)
		quarter(working, 3, 8, 9, 14)
		quarter(working, 4, 5, 10, 15)
	end
	local out = table.create(16)
	for i = 1, 16 do
		out[i] = string.pack("<I4", (working[i] + state[i]) % TWO32)
	end
	return table.concat(out)
end

local function chacha20(key: string, counter: number, nonce: string, data: string): string
	local out = buffer.create(#data)
	local position = 0
	while position < #data do
		local block = chachaBlock(key, counter, nonce)
		counter += 1
		for i = 1, math.min(64, #data - position) do
			buffer.writeu8(out, position + i - 1, bxor(string.byte(data, position + i), string.byte(block, i)))
		end
		position += 64
	end
	return buffer.tostring(out)
end

--- ChaCha20 keystream XOR (RFC 8439 §2.4) - for the random generator; the AEAD below uses it with counter 1.
Crypto.chacha20 = chacha20

-- ---------------------------------------------------------------------------------------------------------------
-- Poly1305 (port of TweetNaCl crypto_onetimeauth: 17 limbs of 8 bits)

local MINUSP = { [0] = 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 }

local function add1305(h: { number }, c: { number })
	local u = 0
	for j = 0, 16 do
		u += h[j] + c[j]
		h[j] = u % 256
		u = floor(u / 256)
	end
end

local function poly1305(msg: string, key: string): string
	local r, h, c, x = table.create(17, 0), table.create(17, 0), table.create(17, 0), table.create(17, 0)
	for j = 0, 16 do
		r[j], h[j] = 0, 0
	end
	for j = 0, 15 do
		r[j] = string.byte(key, j + 1)
	end
	r[3] = band(r[3], 15)
	r[4] = band(r[4], 252)
	r[7] = band(r[7], 15)
	r[8] = band(r[8], 252)
	r[11] = band(r[11], 15)
	r[12] = band(r[12], 252)
	r[15] = band(r[15], 15)
	local n, at = #msg, 1
	while n > 0 do
		for j = 0, 16 do
			c[j] = 0
		end
		local j = 0
		while j < 16 and j < n do
			c[j] = string.byte(msg, at + j)
			j += 1
		end
		c[j] = 1
		at += j
		n -= j
		add1305(h, c)
		for i = 0, 16 do
			local sum = 0
			for k = 0, 16 do
				sum += h[k] * (if k <= i then r[i - k] else 320 * r[i + 17 - k])
			end
			x[i] = sum
		end
		for i = 0, 16 do
			h[i] = x[i]
		end
		local u = 0
		for k = 0, 15 do
			u += h[k]
			h[k] = u % 256
			u = floor(u / 256)
		end
		u += h[16]
		h[16] = u % 4
		u = 5 * floor(u / 4)
		for k = 0, 15 do
			u += h[k]
			h[k] = u % 256
			u = floor(u / 256)
		end
		u += h[16]
		h[16] = u
	end
	local g = table.clone(h)
	add1305(h, MINUSP)
	if h[16] >= 128 then -- h - p was negative: keep h
		h = g
	end
	for j = 0, 15 do
		c[j] = string.byte(key, j + 17)
	end
	c[16] = 0
	add1305(h, c)
	return toString(h, 16)
end

Crypto.poly1305 = poly1305

-- ---------------------------------------------------------------------------------------------------------------
-- ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)

local function pad16(n: number): string
	return string.rep("\0", (16 - n % 16) % 16)
end

local function aeadTag(key: string, nonce: string, aad: string, ciphertext: string): string
	local otk = string.sub(chachaBlock(key, 0, nonce), 1, 32)
	local data = aad
		.. pad16(#aad)
		.. ciphertext
		.. pad16(#ciphertext)
		.. string.pack("<I4I4", #aad % TWO32, floor(#aad / TWO32))
		.. string.pack("<I4I4", #ciphertext % TWO32, floor(#ciphertext / TWO32))
	return poly1305(data, otk)
end

function Crypto.aeadSeal(key: string, nonce: string, plaintext: string, aad: string): string
	local ciphertext = chacha20(key, 1, nonce, plaintext)
	return ciphertext .. aeadTag(key, nonce, aad, ciphertext)
end

--- Decrypts or returns nil (tag wrong).
function Crypto.aeadOpen(key: string, nonce: string, sealed: string, aad: string): string?
	if #sealed < 16 then
		return nil
	end
	local ciphertext, tag = string.sub(sealed, 1, #sealed - 16), string.sub(sealed, -16)
	local expected = aeadTag(key, nonce, aad, ciphertext)
	local diff = 0
	for i = 1, 16 do
		diff = bor(diff, bxor(string.byte(tag, i), string.byte(expected, i)))
	end
	if diff ~= 0 then
		return nil
	end
	return chacha20(key, 1, nonce, ciphertext)
end

-- ---------------------------------------------------------------------------------------------------------------
-- Field GF(2^255-19): port of TweetNaCl (16 limbs of 16 bits, 0-based like the original)

type GF = { number }

local function gf(init: { number }?): GF
	local r = table.create(16, 0)
	r[0] = 0
	if init then
		for i = 0, #init - 1 do
			r[i] = init[i + 1]
		end
	end
	return r
end

local gf0 = gf()
local gf1 = gf({ 1 })
local _121665 = gf({ 0xdb41, 1 })
local D = gf({ 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 })
local D2 = gf({ 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 })
local X = gf({ 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 })
local Y = gf({ 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 })
local I = gf({ 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 })

local function set25519(r: GF, a: GF)
	for i = 0, 15 do
		r[i] = a[i]
	end
end

local function car25519(o: GF)
	local c = 1
	for i = 0, 15 do
		local v = o[i] + c + 65535
		c = floor(v / 65536)
		o[i] = v - c * 65536
	end
	o[0] += c - 1 + 37 * (c - 1)
end

-- Conditional swap by arithmetic (b is 0 or 1): exact on doubles, also for negative limbs.
local function sel25519(p: GF, q: GF, b: number)
	for i = 0, 15 do
		local t = b * (q[i] - p[i])
		p[i] += t
		q[i] -= t
	end
end

local function pack25519(o: { number }, n: GF)
	local m, t = gf(), gf()
	for i = 0, 15 do
		t[i] = n[i]
	end
	car25519(t)
	car25519(t)
	car25519(t)
	for _ = 1, 2 do
		m[0] = t[0] - 0xffed
		for i = 1, 14 do
			m[i] = t[i] - 0xffff - (if m[i - 1] < 0 then 1 else 0)
			m[i - 1] %= 65536
		end
		m[15] = t[15] - 0x7fff - (if m[14] < 0 then 1 else 0)
		local b = if m[15] < 0 then 1 else 0
		m[14] %= 65536
		sel25519(t, m, 1 - b)
	end
	for i = 0, 15 do
		o[2 * i] = t[i] % 256
		o[2 * i + 1] = floor(t[i] / 256)
	end
end

local function bytesEqual32(a: { number }, b: { number }): boolean
	local diff = 0
	for i = 0, 31 do
		diff = bor(diff, bxor(a[i], b[i]))
	end
	return diff == 0
end

local function neq25519(a: GF, b: GF): boolean
	local c, d = table.create(32, 0), table.create(32, 0)
	pack25519(c, a)
	pack25519(d, b)
	return not bytesEqual32(c, d)
end

local function par25519(a: GF): number
	local d = table.create(32, 0)
	pack25519(d, a)
	return d[0] % 2
end

local function unpack25519(o: GF, n: { number })
	for i = 0, 15 do
		o[i] = n[2 * i] + n[2 * i + 1] * 256
	end
	o[15] %= 32768
end

local function A(o: GF, a: GF, b: GF)
	for i = 0, 15 do
		o[i] = a[i] + b[i]
	end
end

local function Z(o: GF, a: GF, b: GF)
	for i = 0, 15 do
		o[i] = a[i] - b[i]
	end
end

local T31 = table.create(31, 0)
local function M(o: GF, a: GF, b: GF)
	local t = T31
	for i = 0, 30 do
		t[i] = 0
	end
	for i = 0, 15 do
		local ai = a[i]
		for j = 0, 15 do
			t[i + j] += ai * b[j]
		end
	end
	for i = 0, 14 do
		t[i] += 38 * t[i + 16]
	end
	for i = 0, 15 do
		o[i] = t[i]
	end
	car25519(o)
	car25519(o)
end

local function S(o: GF, a: GF)
	M(o, a, a)
end

local function inv25519(o: GF, i: GF)
	local c = gf()
	set25519(c, i)
	for a = 253, 0, -1 do
		S(c, c)
		if a ~= 2 and a ~= 4 then
			M(c, c, i)
		end
	end
	set25519(o, c)
end

local function pow2523(o: GF, i: GF)
	local c = gf()
	set25519(c, i)
	for a = 250, 0, -1 do
		S(c, c)
		if a ~= 1 then
			M(c, c, i)
		end
	end
	set25519(o, c)
end

-- ---------------------------------------------------------------------------------------------------------------
-- X25519 (RFC 7748) - TweetNaCl crypto_scalarmult

local function scalarmult(n: { number }, p: { number }): { number }
	local z = table.create(32, 0)
	for i = 0, 30 do
		z[i] = n[i]
	end
	z[31] = bor(band(n[31], 127), 64)
	z[0] = band(z[0], 248)
	local x = gf()
	unpack25519(x, p)
	local a, b, c, d, e, f = gf(), gf(), gf(), gf(), gf(), gf()
	for i = 0, 15 do
		b[i] = x[i]
		a[i], c[i], d[i] = 0, 0, 0
	end
	a[0], d[0] = 1, 1
	for i = 254, 0, -1 do
		local r = band(rshift(z[rshift(i, 3)], band(i, 7)), 1)
		sel25519(a, b, r)
		sel25519(c, d, r)
		A(e, a, c)
		Z(a, a, c)
		A(c, b, d)
		Z(b, b, d)
		S(d, e)
		S(f, a)
		M(a, c, a)
		M(c, b, e)
		A(e, a, c)
		Z(a, a, c)
		S(b, a)
		Z(c, d, f)
		M(a, c, _121665)
		A(a, a, d)
		M(c, c, a)
		M(a, d, f)
		M(d, b, x)
		S(b, e)
		sel25519(a, b, r)
		sel25519(c, d, r)
	end
	inv25519(c, c)
	M(a, a, c)
	local q = table.create(32, 0)
	pack25519(q, a)
	return q
end

local NINE = toArray("\9", 32)

--- X25519 public key of a 32-byte secret.
function Crypto.x25519Public(secret: string): string
	return toString(scalarmult(toArray(secret, 32), NINE), 32)
end

--- X25519 shared secret, or nil if it is all zero (low-order peer key).
function Crypto.x25519(secret: string, peer: string): string?
	local shared = toString(scalarmult(toArray(secret, 32), toArray(peer, 32)), 32)
	if shared == string.rep("\0", 32) then
		return nil
	end
	return shared
end

-- ---------------------------------------------------------------------------------------------------------------
-- Ed25519 (RFC 8032) - TweetNaCl crypto_sign / crypto_sign_open

local function add(p: { GF }, q: { GF })
	local a, b, c, d, e, f, g, h, t = gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf()
	Z(a, p[2], p[1])
	Z(t, q[2], q[1])
	M(a, a, t)
	A(b, p[1], p[2])
	A(t, q[1], q[2])
	M(b, b, t)
	M(c, p[4], q[4])
	M(c, c, D2)
	M(d, p[3], q[3])
	A(d, d, d)
	Z(e, b, a)
	Z(f, d, c)
	A(g, d, c)
	A(h, b, a)
	M(p[1], e, f)
	M(p[2], h, g)
	M(p[3], g, f)
	M(p[4], e, h)
end

local function cswap(p: { GF }, q: { GF }, b: number)
	for i = 1, 4 do
		sel25519(p[i], q[i], b)
	end
end

local function pack(r: { number }, p: { GF })
	local tx, ty, zi = gf(), gf(), gf()
	inv25519(zi, p[3])
	M(tx, p[1], zi)
	M(ty, p[2], zi)
	pack25519(r, ty)
	r[31] = bxor(r[31], par25519(tx) * 128)
end

local function scalarmultPoint(p: { GF }, q: { GF }, s: { number })
	set25519(p[1], gf0)
	set25519(p[2], gf1)
	set25519(p[3], gf1)
	set25519(p[4], gf0)
	for i = 255, 0, -1 do
		local b = band(rshift(s[rshift(i, 3)], band(i, 7)), 1)
		cswap(p, q, b)
		add(q, p)
		add(p, p)
		cswap(p, q, b)
	end
end

local function scalarbase(p: { GF }, s: { number })
	local q = { gf(), gf(), gf(), gf() }
	set25519(q[1], X)
	set25519(q[2], Y)
	set25519(q[3], gf1)
	M(q[4], X, Y)
	scalarmultPoint(p, q, s)
end

local L = { [0] = 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }

local function modL(r: { number }, roff: number, x: { number })
	for i = 63, 32, -1 do
		local carry = 0
		local j = i - 32
		local k = i - 12
		while j < k do
			x[j] += carry - 16 * x[i] * L[j - (i - 32)]
			carry = floor((x[j] + 128) / 256)
			x[j] -= carry * 256
			j += 1
		end
		x[j] += carry
		x[i] = 0
	end
	local carry = 0
	for j = 0, 31 do
		x[j] += carry - floor(x[31] / 16) * L[j]
		carry = floor(x[j] / 256)
		x[j] %= 256
	end
	for j = 0, 31 do
		x[j] -= carry * L[j]
	end
	for i = 0, 31 do
		x[i + 1] += floor(x[i] / 256)
		r[roff + i] = x[i] % 256
	end
end

local function reduce(r: { number })
	local x = table.create(64, 0)
	for i = 0, 63 do
		x[i] = r[i]
	end
	for i = 0, 63 do
		r[i] = 0
	end
	modL(r, 0, x)
end

local function hashArray(s: string): { number }
	return toArray(Crypto.sha512(s), 64)
end

--- Ed25519 public key of a 32-byte seed.
function Crypto.ed25519Public(seed: string): string
	local d = hashArray(seed)
	d[0] = band(d[0], 248)
	d[31] = bor(band(d[31], 127), 64)
	local p = { gf(), gf(), gf(), gf() }
	scalarbase(p, d)
	local pk = table.create(32, 0)
	pack(pk, p)
	return toString(pk, 32)
end

--- Ed25519 signature (64 bytes) of `msg` with a 32-byte seed.
function Crypto.ed25519Sign(seed: string, msg: string): string
	local d = hashArray(seed)
	d[0] = band(d[0], 248)
	d[31] = bor(band(d[31], 127), 64)
	local pk = Crypto.ed25519Public(seed)
	local r = hashArray(toString(d, 32, 32) .. msg)
	reduce(r)
	local p = { gf(), gf(), gf(), gf() }
	scalarbase(p, r)
	local R = table.create(32, 0)
	pack(R, p)
	local Rs = toString(R, 32)
	local h = hashArray(Rs .. pk .. msg)
	reduce(h)
	local x = table.create(64, 0)
	for i = 0, 63 do
		x[i] = 0
	end
	for i = 0, 31 do
		x[i] = r[i]
	end
	for i = 0, 31 do
		for j = 0, 31 do
			x[i + j] += h[i] * d[j]
		end
	end
	local s = table.create(32, 0)
	modL(s, 0, x)
	return Rs .. toString(s, 32)
end

local function unpackneg(r: { GF }, p: { number }): boolean
	local t, chk, num, den, den2, den4, den6 = gf(), gf(), gf(), gf(), gf(), gf(), gf()
	set25519(r[3], gf1)
	unpack25519(r[2], p)
	S(num, r[2])
	M(den, num, D)
	Z(num, num, r[3])
	A(den, r[3], den)
	S(den2, den)
	S(den4, den2)
	M(den6, den4, den2)
	M(t, den6, num)
	M(t, t, den)
	pow2523(t, t)
	M(t, t, num)
	M(t, t, den)
	M(t, t, den)
	M(r[1], t, den)
	S(chk, r[1])
	M(chk, chk, den)
	if neq25519(chk, num) then
		M(r[1], r[1], I)
	end
	S(chk, r[1])
	M(chk, chk, den)
	if neq25519(chk, num) then
		return false
	end
	if par25519(r[1]) == rshift(p[31], 7) then
		Z(r[1], gf0, r[1])
	end
	M(r[4], r[1], r[2])
	return true
end

--- Plain Ed25519 verification (RFC 8032, cofactorless). The strict checks (small-order keys and R, S < L) are in
--- `Crypto.verify`.
function Crypto.ed25519Verify(public: string, msg: string, signature: string): boolean
	if #public ~= 32 or #signature ~= 64 then
		return false
	end
	local q = { gf(), gf(), gf(), gf() }
	local pk = toArray(public, 32)
	if not unpackneg(q, pk) then
		return false
	end
	local h = hashArray(string.sub(signature, 1, 32) .. public .. msg)
	reduce(h)
	local p = { gf(), gf(), gf(), gf() }
	scalarmultPoint(p, q, h)
	scalarbase(q, toArray(string.sub(signature, 33, 64), 32))
	add(p, q)
	local t = table.create(32, 0)
	pack(t, p)
	return bytesEqual32(toArray(string.sub(signature, 1, 32), 32), t)
end

-- ---------------------------------------------------------------------------------------------------------------
-- Bridge rules: domain separation, strict verification, one-time keys

local function weakSet(): { [string]: boolean }
	local function fromHex(h: string): string
		return (string.gsub(h, "..", function(byte)
			return string.char(tonumber(byte, 16) :: number)
		end))
	end
	local values = {
		string.rep("\0", 32),
		"\1" .. string.rep("\0", 31),
		fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	}
	for _, low in { 0xec, 0xed, 0xee } do
		table.insert(values, string.char(low) .. string.rep("\255", 30) .. "\127")
	end
	local out = {}
	for _, value in values do
		out[value] = true
		out[string.sub(value, 1, 31) .. string.char(bor(string.byte(value, 32), 0x80))] = true
	end
	return out
end

local WEAK = weakSet()
local ORDER_L = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }

local function sBelowL(s: string): boolean
	for i = 32, 1, -1 do
		local byte = string.byte(s, i)
		if byte < ORDER_L[i] then
			return true
		elseif byte > ORDER_L[i] then
			return false
		end
	end
	return false -- equal to L
end

function Crypto.isWeakKey(key: string): boolean
	return WEAK[key] == true
end

local function domainMessage(domain: string, message: string): string
	return "bridge4/" .. domain .. "\n" .. message
end

function Crypto.sign(seed: string, domain: string, message: string): string
	return Crypto.ed25519Sign(seed, domainMessage(domain, message))
end

--- Strict verification like the core: small-order keys and R refused, S < L, then RFC 8032.
function Crypto.verify(public: string, domain: string, message: string, signature: string): boolean
	if #public ~= 32 or #signature ~= 64 then
		return false
	end
	if WEAK[public] or WEAK[string.sub(signature, 1, 32)] then
		return false
	end
	if not sBelowL(string.sub(signature, 33, 64)) then
		return false
	end
	return Crypto.ed25519Verify(public, domainMessage(domain, message), signature)
end

return Crypto
