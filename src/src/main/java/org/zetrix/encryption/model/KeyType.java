package org.zetrix.encryption.model;

public enum KeyType {
    ED25519  (0x01, 0x01),
    SM2      (0x02, 0x02),
    DILITHIUM3(0x05, 0x04),
    HYBRID   (0x06, 0x06);

    private final int signTypeByte;
    private final int addressByte;

    KeyType(int signTypeByte, int addressByte) {
        this.signTypeByte = signTypeByte;
        this.addressByte  = addressByte;
    }

    public int getSignTypeByte() { return signTypeByte; }
    public int getAddressByte()  { return addressByte;  }

    /** Look up by sign-type byte (private/public key byte). Returns null if unknown. */
    public static KeyType fromSignTypeByte(int b) {
        for (KeyType t : values()) {
            if (t.signTypeByte == b) return t;
        }
        return null;
    }

    /** Look up by address byte (address encoding byte). Returns null if unknown. */
    public static KeyType fromAddressByte(int b) {
        for (KeyType t : values()) {
            if (t.addressByte == b) return t;
        }
        return null;
    }
}
