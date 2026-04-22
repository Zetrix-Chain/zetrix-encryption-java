package org.zetrix.encryption;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.zetrix.encryption.crypto.keystore.KeyStore;
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
            case SM2:
                assertTrue("ED25519/SM2 address must start with ZTX3", addr.startsWith("ZTX3"));
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
}
