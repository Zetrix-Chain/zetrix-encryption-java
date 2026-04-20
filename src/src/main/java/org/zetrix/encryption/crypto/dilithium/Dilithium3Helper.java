package org.zetrix.encryption.crypto.dilithium;

import org.bouncycastle.pqc.crypto.crystals.dilithium.*;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Dilithium3 (ML-DSA-65, FIPS 204) key generation, signing, and verification
 * via Bouncy Castle PQC.
 *
 * Raw key layout stored in the encoded private key blob:
 *   dil3_priv(4032 B) || dil3_pub(1952 B) = 5984 B total
 *
 * Constants:
 *   DIL3_PRIV_LEN = 4032 B  (CRHBYTES=64, FIPS 204 / ML-DSA-65)
 *   DIL3_PUB_LEN  = 1952 B
 *   DIL3_SIG_LEN  = 3309 B
 */
public class Dilithium3Helper {

    public static final int DIL3_PRIV_LEN = 4032;
    public static final int DIL3_PUB_LEN  = 1952;
    public static final int DIL3_SIG_LEN  = 3309;

    private static final DilithiumParameters PARAMS = DilithiumParameters.dilithium3;

    /** Generate a new Dilithium3 key pair. Returns {privKey(4032B), pubKey(1952B)}. */
    public static byte[][] generateKeyPair() {
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(new SecureRandom(), PARAMS));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();
        DilithiumPublicKeyParameters  pub  = (DilithiumPublicKeyParameters)  kp.getPublic();

        return new byte[][]{ priv.getEncoded(), pub.getEncoded() };
    }

    /** Sign a message. Returns 3309-B signature. */
    public static byte[] sign(byte[] msg, byte[] privKeyBytes) {
        DilithiumPrivateKeyParameters privKey = new DilithiumPrivateKeyParameters(PARAMS, privKeyBytes, null);
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, privKey);
        return signer.generateSignature(msg);
    }

    /** Verify a 3309-B signature against the message and 1952-B public key. */
    public static boolean verify(byte[] msg, byte[] sig, byte[] pubKeyBytes) {
        try {
            DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(PARAMS, pubKeyBytes);
            DilithiumSigner verifier = new DilithiumSigner();
            verifier.init(false, pubKey);
            return verifier.verifySignature(msg, sig);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract the public key from the raw blob stored in the encoded private key.
     * Raw blob = dil3_priv(4032) || dil3_pub(1952); public key is the last 1952 bytes.
     */
    public static byte[] pubKeyFromRawBlob(byte[] rawBlob) {
        return Arrays.copyOfRange(rawBlob, DIL3_PRIV_LEN, DIL3_PRIV_LEN + DIL3_PUB_LEN);
    }
}
