package org.zetrix.encryption.common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.zetrix.encryption.model.KeyType;
import org.zetrix.encryption.utils.hash.SM3Digest;

public class CheckKey {

    public static boolean CheckSum(KeyType type, byte[] key) {
        return checkKey(type, key);
    }

    /**
     * SM3 for SM2 keys/addresses; SHA-256 for all others (ED25519, DILITHIUM3, HYBRID).
     */
    public static byte[] CalHash(KeyType type, byte[] data) {
        if (type == KeyType.SM2) {
            return SM3Digest.Hash(data);
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(data);
            return sha256.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean checkKey(KeyType type, byte[] key) {
        byte[] checkSrc = new byte[key.length - 4];
        byte[] checkSum = new byte[4];
        System.arraycopy(key, 0, checkSrc, 0, checkSrc.length);
        System.arraycopy(key, checkSrc.length, checkSum, 0, 4);

        byte[] hash1 = CalHash(type, checkSrc);
        byte[] hash2 = CalHash(type, hash1);

        byte[] hashSum = new byte[4];
        System.arraycopy(hash2, 0, hashSum, 0, 4);
        return Arrays.equals(hashSum, checkSum);
    }
}
