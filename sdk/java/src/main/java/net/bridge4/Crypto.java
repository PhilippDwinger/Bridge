package net.bridge4;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * All cryptographic primitives of the SDK in one place (docs/02 §4, rule Z10): only the JDK (Ed25519, XDH, ChaCha20-
 * Poly1305, HmacSHA256, SHA-256); HKDF is RFC 5869 over HmacSHA256. Strict checks like the core: small-order keys and
 * R refused, S &lt; L, no all-zero X25519 results.
 */
public final class Crypto {
    private Crypto() {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final byte[] ED_X509 = Enc.fromHex("302a300506032b6570032100");
    private static final byte[] X_X509 = Enc.fromHex("302a300506032b656e032100");
    private static final Set<String> WEAK = weak();

    private static Set<String> weak() {
        byte[][] values = new byte[7][];
        values[0] = new byte[32];
        values[1] = new byte[32];
        values[1][0] = 1;
        values[2] = Enc.fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
        values[3] = Enc.fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
        int[] lows = {0xec, 0xed, 0xee};
        for (int i = 0; i < 3; i++) {
            byte[] value = new byte[32];
            Arrays.fill(value, (byte) 0xff);
            value[0] = (byte) lows[i];
            value[31] = 0x7f;
            values[4 + i] = value;
        }
        Set<String> out = new HashSet<>();
        for (byte[] value : values) {
            out.add(Enc.hex(value));
            byte[] signed = value.clone();
            signed[31] |= (byte) 0x80;
            out.add(Enc.hex(signed));
        }
        return out;
    }

    public static boolean isWeakKey(byte[] key) {
        return WEAK.contains(Enc.hex(key));
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        RANDOM.nextBytes(out);
        return out;
    }

    private static byte[] domain(String domain, byte[] message) {
        return Enc.concat(Enc.utf8("bridge4/" + domain + "\n"), message);
    }

    /** A random source that hands out exactly the given seed (to derive a public key the JDK way). */
    private static final class Seed extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;

        Seed(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(seed, 0, bytes, 0, Math.min(seed.length, bytes.length));
        }
    }

    private static byte[] raw(PublicKey key) {
        byte[] encoded = key.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    static PrivateKey signKey(byte[] seed) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
    }

    public static byte[] signPublic(byte[] seed) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new Seed(seed));
            KeyPair pair = generator.generateKeyPair();
            return raw(pair.getPublic());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static PrivateKey boxKey(byte[] secret) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH").generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, secret));
    }

    private static PublicKey boxPublicKey(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(Enc.concat(X_X509, raw)));
    }

    /** The X25519 public key: the shared secret with the base point 9. */
    public static byte[] boxPublic(byte[] secret) {
        byte[] nine = new byte[32];
        nine[0] = 9;
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(boxKey(secret));
            agreement.doPhase(boxPublicKey(nine), true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] sign(byte[] seed, String domain, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(signKey(seed));
            signature.update(domain(domain, message));
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Strict verification like the core; throws BAD_SIGNATURE. */
    public static void verify(byte[] publicKey, String domain, byte[] message, byte[] signature) throws BridgeException {
        if (publicKey.length != 32 || signature.length != 64) throw BridgeException.signature();
        if (isWeakKey(publicKey) || isWeakKey(Arrays.copyOfRange(signature, 0, 32))) throw BridgeException.signature();
        byte[] s = new byte[32];
        for (int i = 0; i < 32; i++) s[i] = signature[63 - i];
        if (new BigInteger(1, s).compareTo(L) >= 0) throw BridgeException.signature();
        boolean ok;
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Enc.concat(ED_X509, publicKey)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(domain(domain, message));
            ok = verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            ok = false;
        }
        if (!ok) throw BridgeException.signature();
    }

    private static byte[] agree(PrivateKey secret, byte[] peer) throws BridgeException {
        byte[] shared;
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(secret);
            agreement.doPhase(boxPublicKey(peer), true);
            shared = agreement.generateSecret();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new BridgeException("CANNOT_OPEN", "");
        }
        boolean zero = true;
        for (byte b : shared) zero &= b == 0;
        if (zero) throw new BridgeException("CANNOT_OPEN", "");
        return shared;
    }

    /** A new one-time key pair (N1: only made here) agreed with {@code peer}: {one-time public key, shared secret}. */
    public static byte[][] agreeOneTime(byte[] peer) throws BridgeException {
        byte[] secret = randomBytes(32);
        try {
            return new byte[][] {boxPublic(secret), agree(boxKey(secret), peer)};
        } catch (GeneralSecurityException e) {
            throw new BridgeException("CANNOT_OPEN", "");
        }
    }

    public static byte[] agreeStatic(byte[] secret, byte[] peer) throws BridgeException {
        try {
            return agree(boxKey(secret), peer);
        } catch (GeneralSecurityException e) {
            throw new BridgeException("CANNOT_OPEN", "");
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    /** HKDF-SHA256 (RFC 5869) to 32 bytes. */
    public static byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info) {
        try {
            byte[] prk = hmac(salt, ikm);
            return hmac(prk, Enc.concat(info, new byte[] {1}));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Cipher chacha(int mode, byte[] key, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        cipher.updateAAD(aad);
        return cipher;
    }

    public static byte[] aeadSeal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            return chacha(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] aeadOpen(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) throws BridgeException {
        try {
            return chacha(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new BridgeException("CANNOT_OPEN", "");
        }
    }

    public static int leadingZeroBits(byte[] digest) {
        int bits = 0;
        for (byte b : digest) {
            int value = b & 0xff;
            if (value == 0) {
                bits += 8;
                continue;
            }
            return bits + Integer.numberOfLeadingZeros(value) - 24;
        }
        return bits;
    }
}
