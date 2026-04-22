package org.zetrix.encryption.crypto.dilithium;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Dilithium3 (ML-DSA-65, FIPS 204) key generation, signing, and verification
 * via Bouncy Castle 1.80 pqc.crypto.mldsa — the final FIPS 204 implementation.
 *
 * Raw key layout stored in the encoded private key blob:
 *   dil3_priv(4032 B) || dil3_pub(1952 B) = 5984 B total
 *
 * Constants:
 *   DIL3_PRIV_LEN = 4032 B  (CRHBYTES=64, FIPS 204 / ML-DSA-65)
 *   DIL3_PUB_LEN  = 1952 B
 *   DIL3_SIG_LEN  = 3309 B
 *
 * Compatibility note:
 *   BC 1.80's MLDSASigner.init() prepends a FIPS 204 pure-mode context byte sequence
 *   (0x00 || 0x00) to the message digest. The Zetrix blockchain and Node.js SDK use
 *   sign_internal which hashes (tr || msg) directly without any prefix.
 *   We bypass this by calling the protected internalGenerateSignature / internalVerifySignature
 *   methods via reflection, which use initSign(tr, false, null) — no prefix.
 */
public class Dilithium3Helper {

    public static final int DIL3_PRIV_LEN = 4032;
    public static final int DIL3_PUB_LEN  = 1952;
    public static final int DIL3_SIG_LEN  = 3309;

    private static final MLDSAParameters PARAMS = MLDSAParameters.ml_dsa_65;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final Method INTERNAL_SIGN;
    private static final Method INTERNAL_VERIFY;

    static {
        try {
            INTERNAL_SIGN = MLDSASigner.class.getDeclaredMethod(
                    "internalGenerateSignature", byte[].class, byte[].class);
            INTERNAL_SIGN.setAccessible(true);

            INTERNAL_VERIFY = MLDSASigner.class.getDeclaredMethod(
                    "internalVerifySignature", byte[].class, byte[].class);
            INTERNAL_VERIFY.setAccessible(true);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(
                    "BC 1.80 MLDSASigner missing internalGenerateSignature/internalVerifySignature. " +
                    "Upgrade or re-check the Bouncy Castle version.", e);
        }
    }

    /** Generate a new ML-DSA-65 key pair. Returns {privKey(4032B), pubKey(1952B)}. */
    public static byte[][] generateKeyPair() {
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(SECURE_RANDOM, PARAMS));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();
        MLDSAPublicKeyParameters  pub  = (MLDSAPublicKeyParameters)  kp.getPublic();

        return new byte[][]{ priv.getEncoded(), pub.getEncoded() };
    }

    /**
     * Sign a message with ML-DSA-65 using sign_internal (no FIPS 204 context prefix).
     * Returns a 3309-byte signature compatible with the Zetrix blockchain and Node.js SDK.
     */
    public static byte[] sign(byte[] msg, byte[] privKeyBytes) {
        try {
            MLDSAPrivateKeyParameters privKey = new MLDSAPrivateKeyParameters(PARAMS, privKeyBytes);
            MLDSASigner signer = new MLDSASigner();
            signer.init(true, privKey);

            // 32-byte random value for hedged signing (rnd != 0 prevents fault attacks).
            byte[] rnd = new byte[32];
            SECURE_RANDOM.nextBytes(rnd);

            byte[] signature = (byte[]) INTERNAL_SIGN.invoke(signer, msg, rnd);

            if (signature.length != DIL3_SIG_LEN) {
                throw new RuntimeException(
                    String.format("ML-DSA-65 signature length mismatch: expected %d bytes, got %d bytes.",
                        DIL3_SIG_LEN, signature.length));
            }
            return signature;
        } catch (Exception e) {
            Throwable cause = (e.getCause() != null) ? e.getCause() : e;
            throw new RuntimeException("ML-DSA-65 signing failed: " + cause.getMessage(), cause);
        }
    }

    /**
     * Verify a 3309-B ML-DSA-65 signature using verify_internal (no FIPS 204 context prefix).
     */
    public static boolean verify(byte[] msg, byte[] sig, byte[] pubKeyBytes) {
        try {
            MLDSAPublicKeyParameters pubKey = new MLDSAPublicKeyParameters(PARAMS, pubKeyBytes);
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, pubKey);

            return (Boolean) INTERNAL_VERIFY.invoke(verifier, msg, sig);
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
