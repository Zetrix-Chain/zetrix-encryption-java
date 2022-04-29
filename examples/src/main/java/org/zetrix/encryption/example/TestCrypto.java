package org.zetrix.encryption.example;

import com.alibaba.fastjson.JSON;

import org.zetrix.encryption.crypto.keystore.KeyStore;
import org.zetrix.encryption.crypto.keystore.entity.KeyStoreEty;

public class TestCrypto {
	public static void main(String argv[]) {
		String encPrivateKey = "privC11k64jNn1nrdFsFgBMeUW1VC5MvXZX2a13ZYy9vyAVsubcsGWYS";
		String password = "test";
		TestKeyStoreWithPrivateKey(encPrivateKey, password);
		
	}
	
	public static void TestKeyStoreWithPrivateKey(String encPrivateKey, String password) {
		try {
			//KeyStoreEty keyStore = KeyStore.generateKeyStore(password, encPrivateKey);
			//难度
			int n = (int)Math.pow(2, 16);
			KeyStoreEty keyStore = KeyStore.generateKeyStore(password, encPrivateKey,2);
			System.out.println(JSON.toJSONString(keyStore));
			String privateKey = KeyStore.decipherKeyStore(password, keyStore);
			System.out.println(privateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
