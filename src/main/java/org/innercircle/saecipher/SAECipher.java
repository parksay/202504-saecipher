package org.innercircle.saecipher;

public class SAECipher {

    public static final int TYPE_AES_256 = 1;
    public static final int TYPE_RSA_2048 = 2;

    public static SAECipherKey generateKey(int citype) {
        return null;
    }

    public static String encrypt(int citype, SAECipherKey key, String plainText) {
        return "";
    }

    public static String decrypt(int citype, SAECipherKey key, String encrypted) {
        return "";
    }

    public class SAECipherKey {

        public String getKey() {
            return "";
        }

        public SAECipherKey getSecretKey() {
            return null;
        }

        public SAECipherKey getPublicKey() {
            return null;
        }
    }
}
