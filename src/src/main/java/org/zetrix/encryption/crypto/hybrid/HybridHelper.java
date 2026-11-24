package org.zetrix.encryption.crypto.hybrid;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.zetrix.encryption.crypto.dilithium.Dilithium3Helper;

import java.security.KeyPair;
import java.util.Arrays;

/**
 * Hybrid key generation, signing, and verification (ED25519 + Dilithium3).
 *
 * Raw private key layout: ed25519_seed(32) || dil3_priv(4032) || dil3_pub(1952) = 6016 B
 * Raw public  key layout: ed25519_pub(32)  || dil3_pub(1952)                    = 1984 B
 * Signature layout:       ed25519_sig(64)  || dil3_sig(3309)                    = 3373 B
 *
 * Both sub-signatures must be valid for verify() to return true.
 */
public class HybridHelper {

    public static final int ED25519_SEED_LEN = 32;
    public static final int ED25519_PUB_LEN  = 32;
    public static final int ED25519_SIG_LEN  = 64;

    public static final int HYBRID_PRIV_LEN = ED25519_SEED_LEN + Dilithium3Helper.DIL3_PRIV_LEN + Dilithium3Helper.DIL3_PUB_LEN; // 6016
    public static final int HYBRID_PUB_LEN  = ED25519_PUB_LEN  + Dilithium3Helper.DIL3_PUB_LEN;  // 1984
    public static final int HYBRID_SIG_LEN  = ED25519_SIG_LEN  + Dilithium3Helper.DIL3_SIG_LEN;  // 3373

    /**
     * Generate a Hybrid key pair.
     * Returns { rawPriv(6016B), rawPub(1984B) }.
     */
    public static byte[][] generateKeyPair() throws Exception {
        // ED25519
        KeyPairGenerator edGen = new KeyPairGenerator();
        KeyPair edKp = edGen.generateKeyPair();
        EdDSAPrivateKey edPriv = (EdDSAPrivateKey) edKp.getPrivate();
        EdDSAPublicKey  edPub  = (EdDSAPublicKey)  edKp.getPublic();
        byte[] edSeed   = edPriv.getSeed();     // 32 B
        byte[] edPubBytes = edPub.getAbyte();   // 32 B

        // Dilithium3
        byte[][] dil3Kp = Dilithium3Helper.generateKeyPair();
        byte[] dil3Priv = dil3Kp[0]; // 4032 B
        byte[] dil3Pub  = dil3Kp[1]; // 1952 B

        // Concatenate
        byte[] rawPriv = new byte[HYBRID_PRIV_LEN];
        System.arraycopy(edSeed,   0, rawPriv, 0,                                         ED25519_SEED_LEN);
        System.arraycopy(dil3Priv, 0, rawPriv, ED25519_SEED_LEN,                          Dilithium3Helper.DIL3_PRIV_LEN);
        System.arraycopy(dil3Pub,  0, rawPriv, ED25519_SEED_LEN + Dilithium3Helper.DIL3_PRIV_LEN, Dilithium3Helper.DIL3_PUB_LEN);

        byte[] rawPub = new byte[HYBRID_PUB_LEN];
        System.arraycopy(edPubBytes, 0, rawPub, 0,              ED25519_PUB_LEN);
        System.arraycopy(dil3Pub,    0, rawPub, ED25519_PUB_LEN, Dilithium3Helper.DIL3_PUB_LEN);

        return new byte[][]{ rawPriv, rawPub };
    }

    /**
     * Derive the public key from a raw Hybrid private key blob (6016 B).
     * ED25519 pub is re-derived from seed; Dilithium3 pub is read directly from the blob.
     */
    public static byte[] getPublicKey(byte[] rawPriv) {
        byte[] edSeed = Arrays.copyOfRange(rawPriv, 0, ED25519_SEED_LEN);
        byte[] dil3Pub = Arrays.copyOfRange(rawPriv,
                ED25519_SEED_LEN + Dilithium3Helper.DIL3_PRIV_LEN,
                HYBRID_PRIV_LEN);

        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
        EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(edSeed, spec);
        EdDSAPublicKeySpec  pubSpec  = new EdDSAPublicKeySpec(privSpec.getA(), spec);
        byte[] edPub = new EdDSAPublicKey(pubSpec).getAbyte();

        byte[] rawPub = new byte[HYBRID_PUB_LEN];
        System.arraycopy(edPub,   0, rawPub, 0,              ED25519_PUB_LEN);
        System.arraycopy(dil3Pub, 0, rawPub, ED25519_PUB_LEN, Dilithium3Helper.DIL3_PUB_LEN);
        return rawPub;
    }

    /**
     * Sign a message with Hybrid (ED25519 + Dilithium3).
     * Returns ed25519_sig(64B) || dil3_sig(3309B) = 3373 B.
     */
    public static byte[] sign(byte[] msg, byte[] rawPriv) throws Exception {
        // Validate input key size per FIPS 204 Hybrid specification
        if (rawPriv.length != HYBRID_PRIV_LEN) {
            throw new IllegalArgumentException(
                String.format("Hybrid private key size mismatch: expected %d bytes, got %d bytes",
                    HYBRID_PRIV_LEN, rawPriv.length));
        }
        
        // ED25519 sign
        byte[] edSeed = Arrays.copyOfRange(rawPriv, 0, ED25519_SEED_LEN);
        byte[] edSig = signEd25519(msg, edSeed);
        
        // Validate ED25519 signature size
        if (edSig.length != ED25519_SIG_LEN) {
            throw new RuntimeException(
                String.format("ED25519 signature size mismatch: expected %d bytes, got %d bytes",
                    ED25519_SIG_LEN, edSig.length));
        }

        // Dilithium3 sign
        byte[] dil3PrivBlob = Arrays.copyOfRange(rawPriv, ED25519_SEED_LEN,
                ED25519_SEED_LEN + Dilithium3Helper.DIL3_PRIV_LEN);
        byte[] dil3Sig = Dilithium3Helper.sign(msg, dil3PrivBlob);

        byte[] combined = new byte[HYBRID_SIG_LEN];
        System.arraycopy(edSig,   0, combined, 0,              ED25519_SIG_LEN);
        System.arraycopy(dil3Sig, 0, combined, ED25519_SIG_LEN, Dilithium3Helper.DIL3_SIG_LEN);
        return combined;
    }

    /**
     * Verify a Hybrid signature. Both ED25519 and Dilithium3 sigs must pass.
     */
    public static boolean verify(byte[] msg, byte[] sig, byte[] rawPub) {
        try {
            if (sig.length != HYBRID_SIG_LEN) return false;

            byte[] edPubBytes = Arrays.copyOfRange(rawPub, 0, ED25519_PUB_LEN);
            byte[] dil3PubBytes = Arrays.copyOfRange(rawPub, ED25519_PUB_LEN, HYBRID_PUB_LEN);

            byte[] edSig   = Arrays.copyOfRange(sig, 0,              ED25519_SIG_LEN);
            byte[] dil3Sig = Arrays.copyOfRange(sig, ED25519_SIG_LEN, HYBRID_SIG_LEN);

            boolean edOk   = verifyEd25519(msg, edSig, edPubBytes);
            boolean dil3Ok = Dilithium3Helper.verify(msg, dil3Sig, dil3PubBytes);
            return edOk && dil3Ok;
        } catch (Exception e) {
            return false;
        }
    }

    // ---- ED25519 helpers (i2p) ----

    static byte[] signEd25519(byte[] msg, byte[] seed) throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
        EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(seed, spec);
        net.i2p.crypto.eddsa.EdDSAEngine engine = new net.i2p.crypto.eddsa.EdDSAEngine(
                java.security.MessageDigest.getInstance("SHA-512"));
        engine.initSign(new net.i2p.crypto.eddsa.EdDSAPrivateKey(privSpec));
        engine.update(msg);
        return engine.sign();
    }

    static boolean verifyEd25519(byte[] msg, byte[] sig, byte[] pubBytes) {
        try {
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
            EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(pubBytes, spec);
            net.i2p.crypto.eddsa.EdDSAEngine engine = new net.i2p.crypto.eddsa.EdDSAEngine(
                    java.security.MessageDigest.getInstance("SHA-512"));
            engine.initVerify(new net.i2p.crypto.eddsa.EdDSAPublicKey(pubSpec));
            engine.update(msg);
            return engine.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }
}
