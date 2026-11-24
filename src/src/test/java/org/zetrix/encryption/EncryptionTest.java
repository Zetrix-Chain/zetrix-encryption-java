package org.zetrix.encryption;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.zetrix.encryption.common.CheckKey;
import org.zetrix.encryption.crypto.keystore.KeyStore;
import org.zetrix.encryption.exception.EncException;
import org.zetrix.encryption.crypto.keystore.entity.KeyStoreEty;
import org.zetrix.encryption.crypto.mnemonic.Mnemonic;
import org.zetrix.encryption.key.PrivateKey;
import org.zetrix.encryption.key.PublicKey;
import org.zetrix.encryption.model.KeyType;

import org.zetrix.encryption.utils.base.Base58;
import org.zetrix.encryption.utils.hex.HexFormat;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class EncryptionTest {

    private final KeyType type;

    public EncryptionTest(KeyType type) {
        this.type = type;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> types() {
        return Arrays.asList(new Object[][]{
            {KeyType.ED25519},
            {KeyType.SM2},
            {KeyType.DILITHIUM3},
            {KeyType.HYBRID},
        });
    }

    // ---- helpers ----

    private PrivateKey newKey() throws Exception {
        return new PrivateKey(type);
    }

    /** Raw key bytes from an encoded private key: 4 header bytes, raw key, 1 zero byte, 4 checksum bytes. */
    private static byte[] rawFromEncoded(String encPrivateKey) {
        byte[] tmp = Base58.decode(encPrivateKey);
        return Arrays.copyOfRange(tmp, 4, tmp.length - 5);
    }

    /** Encode raw key bytes with a valid header and checksum, as the library does. */
    private static String encodeRaw(KeyType type, byte[] raw) {
        byte[] buff = new byte[raw.length + 5];
        buff[0] = (byte) 0xDA;
        buff[1] = (byte) 0x37;
        buff[2] = (byte) 0x9F;
        buff[3] = (byte) type.getSignTypeByte();
        System.arraycopy(raw, 0, buff, 4, raw.length);
        byte[] hash2 = CheckKey.CalHash(type, CheckKey.CalHash(type, buff));
        byte[] out = Arrays.copyOf(buff, buff.length + 4);
        System.arraycopy(hash2, 0, out, buff.length, 4);
        return Base58.encode(out);
    }

    private static void assertKeyRejected(String encPrivateKey) {
        assertFalse(PrivateKey.isPrivateKeyValid(encPrivateKey));
        try {
            new PrivateKey(encPrivateKey);
            fail("new PrivateKey must reject the key");
        } catch (EncException e) {
            assertEquals("Invalid privateKey", e.getMessage());
        }
        try {
            PrivateKey.sign("msg".getBytes(), encPrivateKey);
            fail("PrivateKey.sign must reject the key");
        } catch (EncException e) {
            assertEquals("Invalid privateKey", e.getMessage());
        }
    }

    // ---- tests ----

    @Test
    public void keyGeneration() throws Exception {
        PrivateKey priv = newKey();
        assertNotNull(priv.getEncPrivateKey());
        assertNotNull(priv.getEncPublicKey());
        assertNotNull(priv.getEncAddress());
    }

    @Test
    public void addressPrefix() throws Exception {
        String addr = newKey().getEncAddress();
        switch (type) {
            case ED25519:
                assertTrue("ED25519 address must start with ZTX3", addr.startsWith("ZTX3"));
                break;
            case SM2:
                // The SM2 address byte encodes to ZTX3 or, for about 1 in 8 keys, ZTX4 in Base58.
                assertTrue("SM2 address must start with ZTX3 or ZTX4",
                        addr.startsWith("ZTX3") || addr.startsWith("ZTX4"));
                break;
            case DILITHIUM3:
                assertTrue("Dilithium3 address must start with ZTX4", addr.startsWith("ZTX4"));
                break;
            case HYBRID:
                assertTrue("Hybrid address must start with ZTX5", addr.startsWith("ZTX5"));
                break;
        }
    }

    @Test
    public void validationFlags() throws Exception {
        PrivateKey priv = newKey();
        assertTrue(PrivateKey.isPrivateKeyValid(priv.getEncPrivateKey()));
        assertTrue(PrivateKey.isPublicKeyValid(priv.getEncPublicKey()));
        assertTrue(PrivateKey.isAddressValid(priv.getEncAddress()));
    }

    @Test
    public void staticPublicKeyDerivation() throws Exception {
        PrivateKey priv = newKey();
        String derived = PrivateKey.getEncPublicKey(priv.getEncPrivateKey());
        assertEquals(priv.getEncPublicKey(), derived);
    }

    @Test
    public void staticAddressDerivation() throws Exception {
        PrivateKey priv = newKey();
        String derived = PrivateKey.getEncAddress(priv.getEncPublicKey());
        assertEquals(priv.getEncAddress(), derived);
    }

    @Test
    public void roundTripFromEncodedPrivateKey() throws Exception {
        PrivateKey priv  = newKey();
        PrivateKey priv2 = new PrivateKey(priv.getEncPrivateKey());
        assertEquals(priv.getEncPrivateKey(), priv2.getEncPrivateKey());
        assertEquals(priv.getEncPublicKey(),  priv2.getEncPublicKey());
        assertEquals(priv.getEncAddress(),    priv2.getEncAddress());
    }

    @Test
    public void signVerify() throws Exception {
        PrivateKey priv = newKey();
        byte[] msg = "hello zetrix".getBytes();
        byte[] sig = priv.sign(msg);
        assertTrue(PublicKey.verify(msg, sig, priv.getEncPublicKey()));
    }

    @Test
    public void signatureLength() throws Exception {
        PrivateKey priv = newKey();
        byte[] sig = priv.sign("test".getBytes());
        switch (type) {
            case ED25519:   assertEquals(64,   sig.length); break;
            case SM2:       assertEquals(64,   sig.length); break;
            case DILITHIUM3:assertEquals(3309, sig.length); break;
            case HYBRID:    assertEquals(3373, sig.length); break;
        }
    }

    @Test
    public void verifyFailsOnTamperedMessage() throws Exception {
        PrivateKey priv = newKey();
        byte[] msg = "original".getBytes();
        byte[] sig = priv.sign(msg);
        assertFalse(PublicKey.verify("tampered".getBytes(), sig, priv.getEncPublicKey()));
    }

    @Test
    public void staticSign() throws Exception {
        PrivateKey priv = newKey();
        byte[] msg = "static sign test".getBytes();
        byte[] sig = PrivateKey.sign(msg, priv.getEncPrivateKey());
        assertTrue(PublicKey.verify(msg, sig, priv.getEncPublicKey()));
    }

    @Test
    public void crossTypeVerifyFails() throws Exception {
        PrivateKey signerA = newKey();
        // generate a different key of a different type (ED25519 is always available)
        KeyType otherType = (type == KeyType.ED25519) ? KeyType.SM2 : KeyType.ED25519;
        PrivateKey signerB = new PrivateKey(otherType);
        byte[] msg = "cross type".getBytes();
        byte[] sig = signerA.sign(msg);
        // verify with wrong public key type must not throw — just return false
        try {
            boolean result = PublicKey.verify(msg, sig, signerB.getEncPublicKey());
            assertFalse("Cross-type verify must return false", result);
        } catch (Exception e) {
            // acceptable — some implementations may throw on incompatible key+sig
        }
    }

    @Test
    public void keyStoreRoundTrip() throws Exception {
        PrivateKey priv = newKey();
        String encPriv = priv.getEncPrivateKey();
        String password = "test-pass-123";
        KeyStoreEty ks = KeyStore.generateKeyStore(password, encPriv, 2);
        assertEquals(encPriv, KeyStore.decipherKeyStore(password, ks));
    }

    @Test
    public void keyStoreWrongPasswordFails() throws Exception {
        PrivateKey priv = newKey();
        KeyStoreEty ks = KeyStore.generateKeyStore("correct", priv.getEncPrivateKey(), 2);
        try {
            String recovered = KeyStore.decipherKeyStore("wrong", ks);
            // If no exception, the recovered key must not be valid
            assertFalse("Wrong password must not recover a valid key",
                PrivateKey.isPrivateKeyValid(recovered));
        } catch (Exception e) {
            // Expected — wrong password throws
        }
    }

    // ---- non-parameterized tests (ED25519 only for mnemonic) ----

    @Test
    public void mnemonicDeterministicDerivation() throws Exception {
        if (type != KeyType.ED25519) return; // mnemonic only defined for ED25519
        List<String> words = Arrays.asList(
            "field","resemble","board","rain","amazing","gap",
            "aisle","debris","clay","frequent","usage","industry"
        );
        List<String> paths = Arrays.asList("M/44H/526H/1H/0/0");
        List<String> keys = Mnemonic.generatePrivateKeys(words, paths);
        assertEquals(1, keys.size());
        assertTrue(PrivateKey.isPrivateKeyValid(keys.get(0)));
        // deterministic: same words+path always produce same key
        List<String> keys2 = Mnemonic.generatePrivateKeys(words, paths);
        assertEquals(keys.get(0), keys2.get(0));
    }

    @Test
    public void cfcaByteRejected() throws Exception {
        if (type != KeyType.ED25519) return; // run once

        // Private key: craft a blob with valid magic (0xDA 0x37 0x9F) but type byte 0x04
        // (CFCA byte — not in whitelist {0x01, 0x02, 0x05, 0x06}). Checksum is zeros;
        // the whitelist check fires before checksum so this exercises fromSignTypeByte rejection.
        byte[] privBlob = new byte[41]; // 4 header + 32 raw + 1 zero pad + 4 checksum
        privBlob[0] = (byte) 0xDA;
        privBlob[1] = (byte) 0x37;
        privBlob[2] = (byte) 0x9F;
        privBlob[3] = (byte) 0x04; // CFCA sign type byte — not whitelisted
        assertFalse("CFCA sign byte 0x04 must be rejected as private key",
            PrivateKey.isPrivateKeyValid(Base58.encode(privBlob)));

        // Public key: craft a hex-encoded blob with magic 0xB0 and type byte 0x04
        byte[] pubBlob = new byte[38]; // 2 header + 32 raw + 4 checksum
        pubBlob[0] = (byte) 0xB0;
        pubBlob[1] = (byte) 0x04; // CFCA sign type byte — not whitelisted
        assertFalse("CFCA sign byte 0x04 must be rejected as public key",
            PrivateKey.isPublicKeyValid(HexFormat.byteToHex(pubBlob)));
    }

    @Test
    public void invalidPrivateKeyErrorDoesNotContainKey() throws Exception {
        String key = newKey().getEncPrivateKey();
        // Change one character in the middle: still Base58, but the checksum no longer matches.
        int i = key.length() / 2;
        char c = key.charAt(i) == 'a' ? 'b' : 'a';
        String wrong = key.substring(0, i) + c + key.substring(i + 1);
        for (int n = 0; n < 2; n++) {
            try {
                if (n == 0) new PrivateKey(wrong); else PrivateKey.getEncPublicKey(wrong);
                fail("a key with a wrong checksum must be rejected");
            } catch (EncException e) {
                assertEquals("Invalid privateKey", e.getMessage());
                assertFalse(e.getMessage().contains(wrong));
            }
        }
    }

    @Test
    public void privateKeyPassedAsPublicKeyIsNotEchoed() throws Exception {
        // Callers can pass a private key where a public key is expected, e.g. PrivateKey.getEncAddress(String).
        String key = newKey().getEncPrivateKey();
        try {
            PrivateKey.getEncAddress(key);
            fail("a private key must not be accepted as a public key");
        } catch (EncException e) {
            assertEquals("Invalid publicKey", e.getMessage());
        }
        try {
            PublicKey.verify("msg".getBytes(), new byte[64], key);
            fail("a private key must not be accepted as a public key");
        } catch (EncException e) {
            assertFalse(e.getMessage().contains(key));
        }
    }

    @Test
    public void truncatedPrivateKeyWithValidChecksumRejected() throws Exception {
        byte[] raw = rawFromEncoded(newKey().getEncPrivateKey());
        assertKeyRejected(encodeRaw(type, Arrays.copyOf(raw, raw.length - 1)));
        assertKeyRejected(encodeRaw(type, Arrays.copyOf(raw, raw.length + 1)));
    }

    @Test
    public void privateKeyWithForeignDilithiumPublicKeyRejected() throws Exception {
        if (type != KeyType.DILITHIUM3 && type != KeyType.HYBRID) return;
        byte[] rawA = rawFromEncoded(newKey().getEncPrivateKey());
        byte[] rawB = rawFromEncoded(newKey().getEncPrivateKey());
        // Both layouts end with the 1,952-byte Dilithium3 public key: put key B's there.
        int pubLen = 1952;
        byte[] mixed = rawA.clone();
        System.arraycopy(rawB, rawB.length - pubLen, mixed, mixed.length - pubLen, pubLen);
        assertKeyRejected(encodeRaw(type, mixed));
    }

    @Test
    public void signatureWithWrongLengthRejected() throws Exception {
        PrivateKey priv = newKey();
        byte[] msg = "hello zetrix".getBytes();
        byte[] sig = priv.sign(msg);
        String pub = priv.getEncPublicKey();
        byte[] padded = Arrays.copyOf(sig, sig.length + 8);
        Arrays.fill(padded, sig.length, padded.length, (byte) 0x5A);
        assertFalse("signature with bytes appended must not verify", PublicKey.verify(msg, padded, pub));
        assertFalse("signature with one byte appended must not verify",
                PublicKey.verify(msg, Arrays.copyOf(sig, sig.length + 1), pub));
        assertFalse("truncated signature must not verify",
                PublicKey.verify(msg, Arrays.copyOf(sig, sig.length - 1), pub));
        assertFalse("empty signature must not verify", PublicKey.verify(msg, new byte[0], pub));
    }
}
