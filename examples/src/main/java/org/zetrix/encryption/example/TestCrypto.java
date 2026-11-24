package org.zetrix.encryption.example;

import com.alibaba.fastjson.JSON;

import org.zetrix.encryption.crypto.keystore.KeyStore;
import org.zetrix.encryption.crypto.keystore.entity.KeyStoreEty;
import org.zetrix.encryption.key.PrivateKey;
import org.zetrix.encryption.model.KeyType;

public class TestCrypto {
	public static void main(String argv[]) throws Exception {
		String password = "test";
		for (KeyType type : new KeyType[]{KeyType.ED25519, KeyType.SM2, KeyType.DILITHIUM3, KeyType.HYBRID}) {
			System.out.println("\n================ KeyStore: " + type + " ================");
			String encPrivateKey = new PrivateKey(type).getEncPrivateKey();
			TestKeyStoreWithPrivateKey(encPrivateKey, password);
		}
	}

	public static void TestKeyStoreWithPrivateKey(String encPrivateKey, String password) {
		try {
			KeyStoreEty keyStore = KeyStore.generateKeyStore(password, encPrivateKey, 2);
			System.out.println(JSON.toJSONString(keyStore));
			String recovered = KeyStore.decipherKeyStore(password, keyStore);
			System.out.println("recovered equals original: " + encPrivateKey.equals(recovered));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
