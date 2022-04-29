package org.zetrix.encryption.utils.hash;

import org.zetrix.encryption.utils.hex.HexFormat;

public class HashUtil {
	/**
	 * generate hex string of hash
	 * @param src
	 * @return hex string of hash
	 */
	public static String GenerateHashHex(byte[] src) {
		Sha256 sha256 = new Sha256(src);
		byte[] hash = sha256.finish();
		return HexFormat.byteToHex(hash).toLowerCase();
	}
}
