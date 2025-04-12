package org.innercircle.saecipher;


import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class SAECipher {

    public static final int TYPE_AES_256 = 1;
    public static final int TYPE_RSA_2048 = 2;

    public static SAECipherKey generateKey(int citype) {
        try {

            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            SecretKey secretKey = null;
            switch (citype) {
                case TYPE_AES_256:
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    secretKey = keyGen.generateKey();
                    break;
                case TYPE_RSA_2048:
                    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                    gen.initialize(2048);
                    KeyPair keyPair = gen.generateKeyPair();
                    privateKey = keyPair.getPrivate();
                    publicKey = keyPair.getPublic();
                    break;
                default:
                    System.out.println("citype = " + citype);
                    break;
                }
            SAECipherKey saeCipherKey = new SAECipherKey(secretKey, publicKey, privateKey);
            return saeCipherKey;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    public static String encrypt(int citype, SAECipherKey key, String plainText) {
        String encrypted = null;
        switch (citype) {
            case TYPE_AES_256:
                encrypted = encryptAes(TYPE_AES_256, key, plainText);
                break;
            case TYPE_RSA_2048:
                encrypted = encryptRsa(TYPE_RSA_2048, key, plainText);
                break;
            default:
                System.out.println("citype = " + citype);
                break;
        }
        return encrypted;
    }

    public static String encryptAes(int citype, SAECipherKey key, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
            byte[] plainBytes = plainText.getBytes();
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("encryptedText ::: ");
            System.out.println(encryptedText);
            return encryptedText;
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encryptRsa(int citype, SAECipherKey key, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
            byte[] plainBytes = plainText.getBytes();
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("encrypte >>>>>>>>>" );
            System.out.println(encryptedText);
            return encryptedText;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public static String decrypt(int citype, SAECipherKey key, String encryptedText) {
        String decrypted = null;
        switch (citype) {
            case TYPE_AES_256:
                decrypted = decryptAes(TYPE_AES_256, key, encryptedText);
                break;
            case TYPE_RSA_2048:
                decrypted = decryptRsa(TYPE_RSA_2048, key, encryptedText);
                break;
            default:
                System.out.println("citype = " + citype);
                break;
        }
        return decrypted;
    }
    public static String decryptAes(int citype, SAECipherKey key, String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey());
            byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
            byte[] plainBytes = cipher.doFinal(encryptedBytes);
            String plainText = new String(plainBytes);
            System.out.println("decrypted >>>>>>> ");
            System.out.println(plainText);
            return plainText;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptRsa(int citype, SAECipherKey key, String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key.getPrivateKey());
            byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            System.out.println("decrypted >>>>>>> ");
            System.out.println(decryptedText);
            return decryptedText;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String sign(SAECipherKey myKey, String msg) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(myKey.getPrivateKey());
            signature.update(msg.getBytes());
            byte[] signedBytes = signature.sign();
            String signedText = Base64.getEncoder().encodeToString(signedBytes);
            System.out.println("signedBytes === ");
            System.out.println(signedBytes.length);

            return signedText;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


    public static boolean verify(SAECipherKey myKey, String msg, String signedText) {
        try {
            byte[] signedBytes = Base64.getDecoder().decode(signedText);
            byte[] msgBytes = msg.getBytes();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(myKey.getPublicKey());
            verifier.update(msgBytes);
            boolean isVerified = verifier.verify(signedBytes);
            System.out.println("signedText == ");
            System.out.println(signedText);
            System.out.println("signedBytes == ");
            System.out.println(signedBytes.length);
            return isVerified;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
//    public class SAECipherKey {
//
//        public String getKey() {
//            return "";
//        }
//
//        public SAECipherKey getSecretKey() {
//            return null;
//        }
//
//        public SAECipherKey getPublicKey() {
//            return null;
//        }
//    }
}
