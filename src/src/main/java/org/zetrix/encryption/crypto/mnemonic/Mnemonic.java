package org.zetrix.encryption.crypto.mnemonic;

import org.zetrix.encryption.exception.EncException;
import org.zetrix.encryption.key.PrivateKey;
import org.zetrix.encryption.model.KeyType;
import org.bitcoinj.crypto.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * @Author riven
 * @Date 2018/9/12 10:31
 */
public class Mnemonic {
    public static List<String> generateMnemonicCode(byte[] random) throws EncException {
        if (random.length != 16) {
            throw new EncException("The length of random must be 16");
        }

        List<String> mnemonicCodes;
        try {
            mnemonicCodes = MnemonicCode.INSTANCE.toMnemonic(random);
        } catch (MnemonicException.MnemonicLengthException e) {
            throw new EncException(e.getMessage());
        }

        if (null == mnemonicCodes || mnemonicCodes.size() == 0) {
            throw new EncException("Failed to generate mnemonic codes");
        }

        return mnemonicCodes;
    }

    /**
     * Convenience overload — generates ED25519 keys (original behaviour).
     */
    public static List<String> generatePrivateKeys(List<String> mnemonicCodes, List<String> hdPaths) throws EncException {
        return generatePrivateKeys(mnemonicCodes, hdPaths, KeyType.ED25519);
    }

    /**
     * Generate ED25519 private keys from BIP39 mnemonic + HD paths.
     * Only ED25519 is supported: BIP32 seed derivation yields a 32-byte scalar
     * that maps directly to an ED25519 seed. PQC types (SM2, DILITHIUM3, HYBRID)
     * require dedicated key generation via {@link PrivateKey#PrivateKey(KeyType)}.
     *
     * @throws UnsupportedOperationException if keyType is not ED25519
     */
    public static List<String> generatePrivateKeys(List<String> mnemonicCodes, List<String> hdPaths, KeyType keyType) throws EncException {
        if (keyType != KeyType.ED25519) {
            throw new UnsupportedOperationException(
                "Mnemonic derivation is only supported for ED25519. " +
                "Use PrivateKey(KeyType) for " + keyType + " key generation.");
        }
        if (null == mnemonicCodes || mnemonicCodes.size() == 0) {
            throw new EncException("The size of mnemonicCodes must be bigger than or equal to 0");
        }
        if (null == hdPaths || hdPaths.size() == 0) {
            throw new EncException("The size of hdPaths must be bigger than or equal to 0");
        }
        byte[] seed = MnemonicCode.toSeed(mnemonicCodes, "");
        DeterministicKey deterministicKey =  HDKeyDerivation.createMasterPrivateKey(seed);

        DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(deterministicKey);
        List<String> privateKeys = new ArrayList<>();
        for (String hdPath : hdPaths) {
            List<ChildNumber> keyPath = HDUtils.parsePath(hdPath);
            DeterministicKey childKey = deterministicHierarchy.get(keyPath, true, true);
            BigInteger privKey = childKey.getPrivKey();
            byte[] bytes = privKey.toByteArray();
            byte[] seeds = new byte[32];
            int startPos = 0;
            int length = 32;
            if (privKey.toByteArray().length == 33) {
                startPos = 1;
            } if (privKey.toByteArray().length == 31) {
                length = 31;
            }
            System.arraycopy(bytes, startPos, seeds, 0, length);
            PrivateKey privateKey = new PrivateKey(seeds);
            privateKeys.add(privateKey.getEncPrivateKey());
        }
        if (privateKeys.size() == 0) {
            throw new EncException("Failed to generate private key with mnemonicCodes");
        }
        return privateKeys;
    }
}
