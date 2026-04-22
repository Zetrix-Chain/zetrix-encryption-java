package org.zetrix.encryption.key;

import java.security.*;
import java.util.Arrays;
import java.util.logging.Logger;

import org.zetrix.encryption.common.CheckKey;
import org.zetrix.encryption.crypto.dilithium.Dilithium3Helper;
import org.zetrix.encryption.crypto.hybrid.HybridHelper;
import org.zetrix.encryption.crypto.sm2.SM2Helper;
import org.zetrix.encryption.exception.EncException;
import org.zetrix.encryption.model.KeyMember;
import org.zetrix.encryption.model.KeyType;
import org.zetrix.encryption.utils.base.Base58;
import org.zetrix.encryption.utils.hex.HexFormat;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class PrivateKey {
    private static final Logger logger = Logger.getLogger(PrivateKey.class.getName());
    private org.zetrix.encryption.key.PublicKey publicKey = new org.zetrix.encryption.key.PublicKey();
    private KeyMember keyMember = new KeyMember();

    /** Generate ED25519 key pair (default). */
    public PrivateKey() throws EncException {
        this(KeyType.ED25519);
    }

    /** Generate key pair for the given type. */
    public PrivateKey(KeyType type) throws EncException {
        try {
            switch (type) {
                case ED25519: {
                    KeyPairGenerator kpg = new KeyPairGenerator();
                    java.security.KeyPair kp = kpg.generateKeyPair();
                    keyMember.setRawSKey(((EdDSAPrivateKey) kp.getPrivate()).getSeed());
                    publicKey.setRawPublicKey(((EdDSAPublicKey) kp.getPublic()).getAbyte());
                    break;
                }
                case SM2: {
                    byte[][] kp = SM2Helper.generateKeyPair();
                    keyMember.setRawSKey(kp[0]);
                    publicKey.setRawPublicKey(kp[1]);
                    break;
                }
                case DILITHIUM3: {
                    byte[][] kp = Dilithium3Helper.generateKeyPair();
                    // Raw blob stored = dil3_priv(4032) || dil3_pub(1952) = 5984 B
                    byte[] rawBlob = new byte[Dilithium3Helper.DIL3_PRIV_LEN + Dilithium3Helper.DIL3_PUB_LEN];
                    System.arraycopy(kp[0], 0, rawBlob, 0,                            Dilithium3Helper.DIL3_PRIV_LEN);
                    System.arraycopy(kp[1], 0, rawBlob, Dilithium3Helper.DIL3_PRIV_LEN, Dilithium3Helper.DIL3_PUB_LEN);
                    keyMember.setRawSKey(rawBlob);
                    publicKey.setRawPublicKey(kp[1]);
                    break;
                }
                case HYBRID: {
                    byte[][] kp = HybridHelper.generateKeyPair();
                    keyMember.setRawSKey(kp[0]);
                    publicKey.setRawPublicKey(kp[1]);
                    break;
                }
                default:
                    throw new EncException("type does not exist");
            }
        } catch (EncException e) {
            throw e;
        } catch (Exception e) {
            throw new EncException(e.getMessage());
        }
        setKeyType(type);
        publicKey.setKeyType(type);
    }

    /** Build from a 32-byte ED25519 seed (backward compat). */
    public PrivateKey(byte[] seed) {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
        EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(seed, spec);
        EdDSAPublicKeySpec  pubSpec  = new EdDSAPublicKeySpec(privSpec.getA(), spec);
        publicKey.setRawPublicKey(new EdDSAPublicKey(pubSpec).getAbyte());
        keyMember.setRawSKey(seed);
        setKeyType(KeyType.ED25519);
        publicKey.setKeyType(KeyType.ED25519);
    }

    /** Load from an encoded private key string. */
    public PrivateKey(String skey) throws EncException {
        getPrivateKey(skey, keyMember);
        publicKey.setKeyType(keyMember.getKeyType());
        byte[] rawPKey = getPublicKey(keyMember);
        publicKey.setRawPublicKey(rawPKey);
        keyMember.setRawPKey(rawPKey);
    }

    public void setKeyType(KeyType keyType)   { keyMember.setKeyType(keyType); }
    public KeyType getKeyType()               { return keyMember.getKeyType(); }
    public void setRawPrivateKey(byte[] raw)  { keyMember.setRawSKey(raw); }
    public byte[] getRawPrivateKey()          { return keyMember.getRawSKey(); }
    public org.zetrix.encryption.key.PublicKey getPublicKey() { return publicKey; }

    public String getEncPrivateKey() throws EncException {
        byte[] raw = keyMember.getRawSKey();
        if (raw == null) throw new EncException("raw private key is null");
        return encPrivateKey(keyMember.getKeyType(), raw);
    }

    public static boolean isPrivateKeyValid(String encPrivateKey) {
        return encPrivateKeyValid(encPrivateKey);
    }

    public String getEncPublicKey() throws EncException {
        byte[] rawPKey = publicKey.getRawPublicKey();
        if (rawPKey == null) throw new EncException("raw public key is null");
        return encPublicKey(keyMember.getKeyType(), rawPKey).toLowerCase();
    }

    public static String getEncPublicKey(String skey) throws EncException {
        KeyMember member = new KeyMember();
        getPrivateKey(skey, member);
        byte[] rawPKey = getPublicKey(member);
        return encPublicKey(member.getKeyType(), rawPKey).toLowerCase();
    }

    public static boolean isPublicKeyValid(String encPublicKey) {
        return org.zetrix.encryption.key.PublicKey.isPublicKeyValid(encPublicKey);
    }

    public String getEncAddress() throws EncException {
        return publicKey.getEncAddress();
    }

    public static String getEncAddress(String pKey) throws EncException {
        return org.zetrix.encryption.key.PublicKey.getEncAddress(pKey);
    }

    public static boolean isAddressValid(String encAddress) {
        return PublicKey.isAddressValid(encAddress);
    }

    public byte[] sign(byte[] msg) throws EncException {
        return signMessage(msg, keyMember);
    }

    public static byte[] sign(byte[] msg, String skey) throws EncException {
        KeyMember member = new KeyMember();
        getPrivateKey(skey, member);
        byte[] rawPKey = getPublicKey(member);
        member.setRawPKey(rawPKey);
        return signMessage(msg, member);
    }

    // ---- Private helpers ----

    /** Decode and validate an encoded private key into the given KeyMember. */
    private static void getPrivateKey(String bSkey, KeyMember member) throws EncException {
        try {
            if (null == bSkey) throw new EncException("Private key cannot be null");

            byte[] skeyTmp = Base58.decode(bSkey);
            if (skeyTmp.length <= 9 || skeyTmp[0] != (byte)0xDA || skeyTmp[1] != (byte)0x37 || skeyTmp[2] != (byte)0x9F) {
                throw new EncException("Private key (" + bSkey + ") is invalid");
            }

            // T6b: whitelist-based type lookup (no ordinal math)
            KeyType type = KeyType.fromSignTypeByte(skeyTmp[3] & 0xFF);
            if (type == null) {
                throw new EncException("Private key (" + bSkey + ") is invalid");
            }

            if (!CheckKey.CheckSum(type, skeyTmp)) {
                throw new EncException("Private key (" + bSkey + ") is invalid");
            }

            byte[] rawSKey = new byte[skeyTmp.length - 9];
            System.arraycopy(skeyTmp, 4, rawSKey, 0, rawSKey.length);
            member.setKeyType(type);
            member.setRawSKey(rawSKey);
        } catch (EncException e) {
            throw e;
        } catch (Exception e) {
            throw new EncException("Invalid privateKey");
        }
    }

    /** Derive the raw public key from the raw private key in a KeyMember. */
    private static byte[] getPublicKey(KeyMember member) throws EncException {
        try {
            switch (member.getKeyType()) {
                case ED25519: {
                    EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
                    EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(member.getRawSKey(), spec);
                    EdDSAPublicKeySpec  pubSpec  = new EdDSAPublicKeySpec(privSpec.getA(), spec);
                    return new EdDSAPublicKey(pubSpec).getAbyte();
                }
                case SM2:
                    return SM2Helper.getPublicKey(member.getRawSKey());
                case DILITHIUM3:
                    // Raw blob = dil3_priv(4032) || dil3_pub(1952); public key is the last 1952 B
                    return Dilithium3Helper.pubKeyFromRawBlob(member.getRawSKey());
                case HYBRID:
                    // Re-derive ed25519_pub from seed[0:32]; read dil3_pub from blob[4064:6016]
                    return HybridHelper.getPublicKey(member.getRawSKey());
                default:
                    throw new EncException("Type does not exist");
            }
        } catch (EncException e) {
            throw e;
        } catch (Exception e) {
            throw new EncException(e.getMessage());
        }
    }

    /** Encode a raw private key to Base58-encoded string. T4 fix: uses getSignTypeByte(). */
    private static String encPrivateKey(KeyType type, byte[] rawSKey) throws EncException {
        if (null == rawSKey) throw new EncException("Private key is null");

        byte[] buff = new byte[rawSKey.length + 5];
        buff[0] = (byte) 0xDA;
        buff[1] = (byte) 0x37;
        buff[2] = (byte) 0x9F;
        buff[3] = (byte) type.getSignTypeByte(); // T4: explicit byte, not ordinal+1
        System.arraycopy(rawSKey, 0, buff, 4, rawSKey.length);

        byte[] hash1 = CheckKey.CalHash(type, buff);
        byte[] hash2 = CheckKey.CalHash(type, hash1);

        byte[] tmp = new byte[buff.length + 4];
        System.arraycopy(buff, 0, tmp, 0, buff.length);
        System.arraycopy(hash2, 0, tmp, buff.length, 4);
        return Base58.encode(tmp);
    }

    /** Validate an encoded private key string. T6 fix: variable length, whitelist type byte. */
    private static boolean encPrivateKeyValid(String encPrivateKey) {
        try {
            if (null == encPrivateKey) return false;
            byte[] tmp = Base58.decode(encPrivateKey);

            if (tmp.length < 10 || tmp[0] != (byte)0xDA || tmp[1] != (byte)0x37 || tmp[2] != (byte)0x9F) {
                return false;
            }
            // T6: detect type from key byte (no ordinal lookup)
            KeyType type = KeyType.fromSignTypeByte(tmp[3] & 0xFF);
            if (type == null) return false;

            // Validate raw key length: blob = 4 header + rawKey + 1 zero + 4 checksum = rawKey + 9
            int expectedRawLen = expectedPrivRawLen(type);
            if (tmp.length - 9 != expectedRawLen) return false;

            int len = tmp.length;
            byte[] buff    = Arrays.copyOfRange(tmp, 0, len - 4);
            byte[] checkSum = Arrays.copyOfRange(tmp, len - 4, len);

            byte[] hash1 = CheckKey.CalHash(type, buff);
            byte[] hash2 = CheckKey.CalHash(type, hash1);
            return Arrays.equals(Arrays.copyOfRange(hash2, 0, 4), checkSum);
        } catch (Exception e) {
            return false;
        }
    }

    private static int expectedPrivRawLen(KeyType type) {
        switch (type) {
            case ED25519:   return 32;
            case SM2:       return 32;
            case DILITHIUM3:return Dilithium3Helper.DIL3_PRIV_LEN + Dilithium3Helper.DIL3_PUB_LEN; // 5984
            case HYBRID:    return HybridHelper.HYBRID_PRIV_LEN; // 6016
            default:        return -1;
        }
    }

    /** Encode a raw public key to hex. T5 fix: uses getSignTypeByte(). */
    static String encPublicKey(KeyType type, byte[] rawPKey) throws EncException {
        if (null == rawPKey) throw new EncException("Public key is null");

        byte[] buff = new byte[rawPKey.length + 2];
        buff[0] = (byte) 0xB0;
        buff[1] = (byte) type.getSignTypeByte(); // T5: explicit byte, not ordinal+1
        System.arraycopy(rawPKey, 0, buff, 2, rawPKey.length);

        byte[] hash1 = CheckKey.CalHash(type, buff);
        byte[] hash2 = CheckKey.CalHash(type, hash1);

        byte[] tmp = new byte[buff.length + 4];
        System.arraycopy(buff,  0, tmp, 0,           buff.length);
        System.arraycopy(hash2, 0, tmp, buff.length, 4);
        return HexFormat.byteToHex(tmp);
    }

    private static byte[] signMessage(byte[] msg, KeyMember member) throws EncException {
        if (null == member.getRawSKey()) throw new EncException("Raw private key is null");
        try {
            switch (member.getKeyType()) {
                case ED25519: {
                    Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
                    EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
                    EdDSAPrivateKeySpec sKeySpec = new EdDSAPrivateKeySpec(member.getRawSKey(), spec);
                    sgr.initSign(new EdDSAPrivateKey(sKeySpec));
                    sgr.update(msg);
                    byte[] sig = sgr.sign();
                    logger.fine("ED25519 signature: " + sig.length + " bytes");
                    return sig;
                }
                case SM2:
                    return SM2Helper.sign(msg, member.getRawSKey());
                case DILITHIUM3: {
                    // Raw blob = dil3_priv(4032) || dil3_pub(1952); use first 4032 B for signing
                    byte[] privKeyBytes = Arrays.copyOfRange(member.getRawSKey(), 0, Dilithium3Helper.DIL3_PRIV_LEN);
                    logger.fine("Dilithium3 signing: private key blob size=" + member.getRawSKey().length + 
                               " bytes, extracted priv key size=" + privKeyBytes.length + " bytes");
                    byte[] sig = Dilithium3Helper.sign(msg, privKeyBytes);
                    logger.fine("Dilithium3 signature: " + sig.length + " bytes");
                    return sig;
                }
                case HYBRID: {
                    logger.fine("Hybrid signing: private key blob size=" + member.getRawSKey().length + " bytes");
                    byte[] sig = HybridHelper.sign(msg, member.getRawSKey());
                    logger.fine("Hybrid signature: " + sig.length + " bytes (ED25519 64B + Dilithium3 3309B)");
                    return sig;
                }
                default:
                    throw new EncException("Type does not exist");
            }
        } catch (EncException e) {
            throw e;
        } catch (NoSuchAlgorithmException e) {
            throw new EncException("System error");
        } catch (InvalidKeyException e) {
            throw new EncException("Invalid privateKey");
        } catch (SignatureException e) {
            throw new EncException("Sign message failed");
        } catch (Exception e) {
            throw new EncException(e.getMessage());
        }
    }
}
