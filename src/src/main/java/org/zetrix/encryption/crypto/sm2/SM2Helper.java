package org.zetrix.encryption.crypto.sm2;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SM2 key generation, public-key derivation, and raw-r||s sign/verify.
 *
 * Key format (raw):
 *   private key: 32 B (big-endian scalar)
 *   public  key: 65 B (uncompressed: 04 || x(32) || y(32))
 *
 * Signature format: raw r||s, 32 B each = 64 B total (no DER).
 *
 * Signing uses BC's SM2Signer (SM3withSM2, default ZA userId "1234567812345678"),
 * matching the sm-crypto JS library used by the Zetrix Node.js SDK.
 */
public class SM2Helper {

    private static final String CURVE_NAME = "sm2p256v1";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static ECDomainParameters ecSpec() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
    }

    /** Generate a new SM2 key pair. Returns {privKey(32B), pubKey(65B)}. */
    public static byte[][] generateKeyPair() {
        ECDomainParameters ec = ecSpec();
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ec, SECURE_RANDOM));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        ECPrivateKeyParameters priv = (ECPrivateKeyParameters) kp.getPrivate();
        ECPublicKeyParameters  pub  = (ECPublicKeyParameters)  kp.getPublic();

        byte[] privBytes = toBytes32(priv.getD());
        byte[] pubBytes  = pub.getQ().getEncoded(false); // uncompressed 04||x||y = 65 B
        return new byte[][]{ privBytes, pubBytes };
    }

    /** Derive the SM2 public key (65 B uncompressed) from a 32-B private scalar. */
    public static byte[] getPublicKey(byte[] privKeyBytes) {
        ECDomainParameters ec = ecSpec();
        BigInteger d = new BigInteger(1, privKeyBytes);
        ECPoint q = ec.getG().multiply(d).normalize();
        return q.getEncoded(false);
    }

    /**
     * Sign message with SM2 (SM3withSM2, default ZA).
     * Returns raw r||s (64 B).
     */
    public static byte[] sign(byte[] msg, byte[] privKeyBytes) throws Exception {
        ECDomainParameters ec = ecSpec();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
                new BigInteger(1, privKeyBytes), ec);

        SM2Signer signer = new SM2Signer();
        signer.init(true, new ParametersWithRandom(privKey, SECURE_RANDOM));
        signer.update(msg, 0, msg.length);
        byte[] derSig = signer.generateSignature();
        return derToRaw(derSig);
    }

    /**
     * Verify raw r||s SM2 signature (64 B) against the original message.
     */
    public static boolean verify(byte[] msg, byte[] rawSig, byte[] pubKeyBytes) {
        // r||s is exactly 64 bytes. Without this check, extra bytes after the first 64
        // were ignored and a padded signature still verified.
        if (rawSig == null || rawSig.length != 64) return false;
        try {
            ECDomainParameters ec = ecSpec();
            ECPoint q = ec.getCurve().decodePoint(pubKeyBytes);
            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(q, ec);

            byte[] derSig = rawToDer(rawSig);

            SM2Signer verifier = new SM2Signer();
            verifier.init(false, pubKey);
            verifier.update(msg, 0, msg.length);
            return verifier.verifySignature(derSig);
        } catch (Exception e) {
            return false;
        }
    }

    // ---- Helpers ----

    private static byte[] toBytes32(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) return b;
        if (b.length == 33 && b[0] == 0) return Arrays.copyOfRange(b, 1, 33);
        byte[] out = new byte[32];
        int srcPos = Math.max(0, b.length - 32);
        int dstPos = 32 - (b.length - srcPos);
        System.arraycopy(b, srcPos, out, dstPos, b.length - srcPos);
        return out;
    }

    private static byte[] derToRaw(byte[] der) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        byte[] out = new byte[64];
        System.arraycopy(toBytes32(r), 0, out, 0,  32);
        System.arraycopy(toBytes32(s), 0, out, 32, 32);
        return out;
    }

    private static byte[] rawToDer(byte[] raw) throws IOException {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(raw, 0,  32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded();
    }
}
