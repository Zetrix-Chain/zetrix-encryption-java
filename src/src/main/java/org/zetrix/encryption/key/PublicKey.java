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
import org.zetrix.encryption.utils.base.Base58;
import org.zetrix.encryption.utils.hex.HexFormat;
import org.zetrix.encryption.model.KeyType;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class PublicKey {
    private static final Logger logger = Logger.getLogger(PublicKey.class.getName());
    private KeyMember keyMember = new KeyMember();

    public PublicKey() {}

    public PublicKey(String encPublicKey) throws EncException {
        getPublicKey(encPublicKey, keyMember);
    }

    public void setEncPublicKey(String encPublicKey) throws EncException {
        getPublicKey(encPublicKey, keyMember);
    }

    public void setRawPublicKey(byte[] rawPKey)  { keyMember.setRawPKey(rawPKey); }
    public byte[] getRawPublicKey()              { return keyMember.getRawPKey(); }
    public void setKeyType(KeyType keyType)      { keyMember.setKeyType(keyType); }
    private KeyType getKeyType()                 { return keyMember.getKeyType(); }

    public String getEncAddress() throws EncException {
        byte[] rawPKey = keyMember.getRawPKey();
        if (null == rawPKey) throw new EncException("public key is null");
        return encAddress(keyMember.getKeyType(), rawPKey);
    }

    public static String getEncAddress(String pKey) throws EncException {
        KeyMember member = new KeyMember();
        getPublicKey(pKey, member);
        return encAddress(member.getKeyType(), member.getRawPKey());
    }

    public static boolean isAddressValid(String encAddress)   { return encAddressValid(encAddress); }
    public static boolean isPublicKeyValid(String encPublicKey) { return encPublicKeyValid(encPublicKey); }

    public boolean verify(byte[] msg, byte[] signMsg) throws EncException {
        return verifyMessage(msg, signMsg, keyMember);
    }

    public static boolean verify(byte[] msg, byte[] signMsg, String encPublicKey) throws EncException {
        KeyMember member = new KeyMember();
        getPublicKey(encPublicKey, member);
        return verifyMessage(msg, signMsg, member);
    }

    /** Decode an encoded public key (hex) into the given KeyMember. */
    private static void getPublicKey(String bPkey, KeyMember member) throws EncException {
        if (null == bPkey) throw new EncException("public key cannot be null");
        if (!HexFormat.isHexString(bPkey)) throw new EncException("Invalid publicKey");

        byte[] buffPKey = HexFormat.hexToByte(bPkey);
        if (buffPKey.length < 6 || buffPKey[0] != (byte)0xB0) {
            throw new EncException("Invalid publicKey");
        }

        // whitelist-based type lookup (no ordinal math, no buffPKey[1] != 1 hardcode)
        KeyType type = KeyType.fromSignTypeByte(buffPKey[1] & 0xFF);
        if (type == null) {
            throw new EncException("Invalid publicKey");
        }

        if (!CheckKey.CheckSum(type, buffPKey)) {
            throw new EncException("Invalid publicKey");
        }

        byte[] rawPKey = new byte[buffPKey.length - 6];
        System.arraycopy(buffPKey, 2, rawPKey, 0, rawPKey.length);
        member.setRawPKey(rawPKey);
        member.setKeyType(type);
    }

    /** Validate an encoded public key string. Whitelists the type byte and detects the type for CalHash. */
    private static boolean encPublicKeyValid(String encPublicKey) {
        try {
            if (null == encPublicKey || !HexFormat.isHexString(encPublicKey)) return false;
            byte[] buff = HexFormat.hexToByte(encPublicKey);
            if (buff.length < 6 || buff[0] != (byte)0xB0) return false;

            KeyType type = KeyType.fromSignTypeByte(buff[1] & 0xFF);
            if (type == null) return false;

            // Validate raw public key length: buff = 2 header + rawPKey + 4 checksum = rawPKey + 6
            int expectedRawLen = expectedPubRawLen(type);
            if (buff.length - 6 != expectedRawLen) return false;

            int len = buff.length;
            byte[] body     = Arrays.copyOfRange(buff, 0, len - 4);
            byte[] checkSum = Arrays.copyOfRange(buff, len - 4, len);

            byte[] hash1 = CheckKey.CalHash(type, body);
            byte[] hash2 = CheckKey.CalHash(type, hash1);
            return Arrays.equals(Arrays.copyOfRange(hash2, 0, 4), checkSum);
        } catch (Exception e) {
            return false;
        }
    }

    private static int expectedPubRawLen(KeyType type) {
        switch (type) {
            case ED25519:   return 32;
            case SM2:       return 65;
            case DILITHIUM3:return Dilithium3Helper.DIL3_PUB_LEN; // 1952
            case HYBRID:    return HybridHelper.HYBRID_PUB_LEN;   // 1984
            default:        return -1;
        }
    }

    /** Encode raw public key + address into Base58 address. */
    private static String encAddress(KeyType type, byte[] rawPKey) {
        byte[] buff = new byte[23];
        buff[0] = (byte) 0xF0;
        buff[1] = (byte) 0x26;
        buff[2] = (byte) type.getAddressByte(); // explicit address byte, not ordinal+1

        byte[] hashPkey = CheckKey.CalHash(type, rawPKey);
        System.arraycopy(hashPkey, 12, buff, 3, 20);

        byte[] hash1 = CheckKey.CalHash(type, buff);
        byte[] hash2 = CheckKey.CalHash(type, hash1);

        byte[] tmp = new byte[27];
        System.arraycopy(buff,  0, tmp, 0,           buff.length);
        System.arraycopy(hash2, 0, tmp, buff.length, 4);
        return Base58.encode(tmp);
    }

    /** Validate an encoded address string. Whitelists the address byte and detects the type for CalHash. */
    private static boolean encAddressValid(String encAddress) {
        try {
            if (null == encAddress) return false;
            byte[] tmp = Base58.decode(encAddress);
            if (tmp.length != 27 || tmp[0] != (byte)0xF0 || tmp[1] != (byte)0x26) return false;

            // whitelist address byte {0x01, 0x02, 0x04, 0x06}; detect type for CalHash
            KeyType type = KeyType.fromAddressByte(tmp[2] & 0xFF);
            if (type == null) return false;

            byte[] body     = Arrays.copyOfRange(tmp, 0, 23);
            byte[] checkSum = Arrays.copyOfRange(tmp, 23, 27);

            byte[] hash1 = CheckKey.CalHash(type, body);
            byte[] hash2 = CheckKey.CalHash(type, hash1);
            return Arrays.equals(Arrays.copyOfRange(hash2, 0, 4), checkSum);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean verifyMessage(byte[] msg, byte[] sig, KeyMember member) {
        try {
            switch (member.getKeyType()) {
                case ED25519: {
                    Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
                    EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
                    EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(member.getRawPKey(), spec);
                    sgr.initVerify(new EdDSAPublicKey(pubSpec));
                    sgr.update(msg);
                    return sgr.verify(sig);
                }
                case SM2:
                    return SM2Helper.verify(msg, sig, member.getRawPKey());
                case DILITHIUM3:
                    return Dilithium3Helper.verify(msg, sig, member.getRawPKey());
                case HYBRID:
                    return HybridHelper.verify(msg, sig, member.getRawPKey());
                default:
                    return false;
            }
        } catch (Exception e) {
            logger.fine("verifyMessage failed for type " + member.getKeyType() + ": " + e.getMessage());
            return false;
        }
    }
}
