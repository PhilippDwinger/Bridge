-- RFC test vectors for the Luau crypto (run with Lune 0.8.9: lune run tests/crypto.luau).
local Crypto = require("../src/Crypto")

local failed = 0
local function hex(s: string): string
	return (string.gsub(s, ".", function(c)
		return string.format("%02x", string.byte(c))
	end))
end
local function unhex(h: string): string
	return (string.gsub(h, "..", function(b)
		return string.char(tonumber(b, 16) :: number)
	end))
end
local function check(name: string, actual: any, expected: any)
	if actual ~= expected then
		failed += 1
		print("FAIL " .. name .. "\n  got      " .. tostring(actual) .. "\n  expected " .. tostring(expected))
	end
end

check("sha256 abc", hex(Crypto.sha256("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("sha256 empty", hex(Crypto.sha256("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
check("sha256 448 bits", hex(Crypto.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
	"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
check("sha512 abc", hex(Crypto.sha512("abc")),
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
check("sha512 896 bits", hex(Crypto.sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
	"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
check("hkdf rfc5869 #1", hex(Crypto.hkdf32(string.rep("\11", 22), unhex("000102030405060708090a0b0c"), unhex("f0f1f2f3f4f5f6f7f8f9"))),
	"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")

-- RFC 8439 §2.8.2
local key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
local nonce = unhex("070000004041424344454647")
local aad = unhex("50515253c0c1c2c3c4c5c6c7")
local plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
local sealed = Crypto.aeadSeal(key, nonce, plaintext, aad)
check("chacha20-poly1305 ct", hex(string.sub(sealed, 1, #plaintext)),
	"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
check("chacha20-poly1305 tag", hex(string.sub(sealed, -16)), "1ae10b594f09e26a7e902ecbd0600691")
check("aead open", Crypto.aeadOpen(key, nonce, sealed, aad), plaintext)
check("aead tamper", Crypto.aeadOpen(key, nonce, sealed, aad .. "x"), nil)

-- RFC 7748 §5.2
check("x25519 #1", hex(Crypto.x25519(unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
	unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")) :: string),
	"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
-- RFC 7748 §6.1 (Alice's public key)
check("x25519 public", hex(Crypto.x25519Public(unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))),
	"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
check("x25519 zero", Crypto.x25519(string.rep("\1", 32), string.rep("\0", 32)), nil)

-- RFC 8032 §7.1 test 1 and 2
local t0 = os.clock()
local seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
check("ed25519 public", hex(Crypto.ed25519Public(seed)), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
local signature = Crypto.ed25519Sign(seed, "")
check("ed25519 sign", hex(signature),
	"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
local t1 = os.clock()
check("ed25519 verify", Crypto.ed25519Verify(Crypto.ed25519Public(seed), "", signature), true)
local t2 = os.clock()
check("ed25519 verify wrong", Crypto.ed25519Verify(Crypto.ed25519Public(seed), "x", signature), false)
local seed2 = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
check("ed25519 #2", hex(Crypto.ed25519Sign(seed2, "\x72")),
	"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
print(string.format("timing: sign %.3fs, verify %.3fs", t1 - t0, t2 - t1))

print(failed == 0 and "crypto: all passed" or ("crypto: " .. failed .. " failed"))
if failed > 0 then
	error("failed")
end
