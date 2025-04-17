package org.innercircle;


import org.innercircle.parksay.SAECipherKey;

import javax.crypto.*;
import java.security.*;
import java.util.Base64;
import java.util.logging.Logger;

public class SAECipher {

    public static final int TYPE_AES_256 = 1;
    public static final int TYPE_RSA_2048 = 2;

    private static final Logger logger = Logger.getLogger(SAECipher.class.getName());

    public static SAECipherKey generateKey(int citype) throws NoSuchAlgorithmException{
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
                logger.info("citype = " + citype);
                break;
            }
        SAECipherKey saeCipherKey = new SAECipherKey(secretKey, publicKey, privateKey);
        return saeCipherKey;
    }


    public static String encrypt(int citype, SAECipherKey key, String plainText) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String encrypted = null;
        switch (citype) {
            case TYPE_AES_256:
                encrypted = encryptAes(TYPE_AES_256, key, plainText);
                break;
            case TYPE_RSA_2048:
                encrypted = encryptRsa(TYPE_RSA_2048, key, plainText);
                break;
            default:
                logger.info("citype = " + citype);
                break;
        }
        return encrypted;
    }

    public static String encryptAes(int citype, SAECipherKey key, String plainText) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
        byte[] plainBytes = plainText.getBytes();
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        logger.info("encryptedText ::: ");
        logger.info(encryptedText);
        return encryptedText;
    }

    public static String encryptRsa(int citype, SAECipherKey key, String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
        byte[] plainBytes = plainText.getBytes();
        byte[] encryptedBytes = cipher.doFinal(plainBytes);
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        logger.info("encrypte >>>>>>>>>" );
        logger.info(encryptedText);
        return encryptedText;
    }

    public static String decrypt(int citype, SAECipherKey key, String encryptedText) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String decrypted = null;
        switch (citype) {
            case TYPE_AES_256:
                decrypted = decryptAes(TYPE_AES_256, key, encryptedText);
                break;
            case TYPE_RSA_2048:
                decrypted = decryptRsa(TYPE_RSA_2048, key, encryptedText);
                break;
            default:
                logger.info("citype = " + citype);
                break;
        }
        return decrypted;
    }
    public static String decryptAes(int citype, SAECipherKey key, String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey());
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        byte[] plainBytes = cipher.doFinal(encryptedBytes);
        String plainText = new String(plainBytes);
        logger.info("decrypted >>>>>>> ");
        logger.info(plainText);
        return plainText;
    }

    public static String decryptRsa(int citype, SAECipherKey key, String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key.getPrivateKey());
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decryptedText = new String(decryptedBytes);
        logger.info("decrypted >>>>>>> ");
        logger.info(decryptedText);
        return decryptedText;
    }

    public static String sign(SAECipherKey myKey, String msg) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(myKey.getPrivateKey());
        signature.update(msg.getBytes());
        byte[] signedBytes = signature.sign();
        String signedText = Base64.getEncoder().encodeToString(signedBytes);
        logger.info("signedBytes === "+ signedBytes.length);

        return signedText;
    }


    public static boolean verify(SAECipherKey myKey, String msg, String signedText) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        byte[] signedBytes = Base64.getDecoder().decode(signedText);
        byte[] msgBytes = msg.getBytes();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(myKey.getPublicKey());
        verifier.update(msgBytes);
        boolean isVerified = verifier.verify(signedBytes);
        logger.info("signedText == ");
        logger.info(signedText);
        logger.info("signedBytes == " + signedBytes.length);
        return isVerified;
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
