package org.zetrix.encryption.example;

import org.zetrix.encryption.crypto.mnemonic.Mnemonic;
import org.zetrix.encryption.key.PrivateKey;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author riven
 * @Date 2018/9/13 10:43
 */
public class TestMnemonic {
    public static void main(String[] argv) {
//        byte[] aesIv = new byte[16];
//        SecureRandom randomIv = new SecureRandom();
//        randomIv.nextBytes(aesIv);
//
//        List<String> mnemonicCodes = Mnemonic.generateMnemonicCode(aesIv);
//        for (String mnemonicCode : mnemonicCodes) {
//            System.out.print(mnemonicCode + " ");
//        }
//        System.out.println();

        // field resemble board rain amazing gap aisle debris clay frequent usage industry
        List<String> mnemonicCodes = new ArrayList<>();
        mnemonicCodes.add("field");
        mnemonicCodes.add("resemble");
        mnemonicCodes.add("board");
        mnemonicCodes.add("rain");
        mnemonicCodes.add("amazing");
        mnemonicCodes.add("gap");
        mnemonicCodes.add("aisle");
        mnemonicCodes.add("debris");
        mnemonicCodes.add("clay");
        mnemonicCodes.add("frequent");
        mnemonicCodes.add("usage");
        mnemonicCodes.add("industry");



        List<String> hdPaths = new ArrayList<>();
        hdPaths.add("M/44H/526H/1H/0/0");
        List<String> privateKeys = Mnemonic.generatePrivateKeys(mnemonicCodes, hdPaths);
        for (String privateKey : privateKeys) {
            if (!PrivateKey.isPrivateKeyValid(privateKey)) {
                System.out.println("private is invalid");
                return;
            }
            System.out.print(privateKey + " " + PrivateKey.getEncAddress(PrivateKey.getEncPublicKey(privateKey)));
        }
        System.out.println();
    }
}
