package org.innercircle.saecipher;


import org.innercircle.saecipher.exception.DecryptFailureException;
import org.innercircle.saecipher.exception.EncryptFailureException;
import org.innercircle.saecipher.exception.KeyFailureException;
import org.innercircle.saecipher.exception.SAECipherException;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SAECipher {


    public static SAECipherKey generateKey(SAECipherType citype) {
        try {
            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            SecretKey secretKey = null;
            switch (citype) {
                case AES_256:
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    secretKey = keyGen.generateKey();
                    break;
                case RSA_2048:
                    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                    gen.initialize(2048);
                    KeyPair keyPair = gen.generateKeyPair();
                    privateKey = keyPair.getPrivate();
                    publicKey = keyPair.getPublic();
                    break;
                default:
                    break;
            }
            SAECipherKey saeCipherKey = new SAECipherKey(secretKey, publicKey, privateKey);
            return saeCipherKey;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyFailureException(e.getMessage(), e);
        }
    }


    public static String encrypt(SAECipherType citype, SAECipherKey key, String plainText) {
        String encrypted = null;
        switch (citype) {
            case AES_256:
                encrypted = encryptAes(SAECipherType.AES_256, key, plainText);
                break;
            case RSA_2048:
                encrypted = encryptRsa(SAECipherType.RSA_2048, key, plainText);
                break;
            default:
                break;
        }
        return encrypted;
    }

    public static String encrypt(SAECipherType citype, String key, String plainText) {
        try {
            SAECipherKey saeKey = null;
            switch (citype) {
                case AES_256:
                    byte[] decodedKey = Base64.getDecoder().decode(key);
                    SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");
                    saeKey = new SAECipherKey(secretKey, null, null);
                    break;
                case RSA_2048:
                    byte[] keyBytes = Base64.getDecoder().decode(key);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(keySpec);
                    saeKey = new SAECipherKey(null, publicKey, null);
                    break;
                default:
                    break;
            }
            return encrypt(citype, saeKey, plainText);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        }
    }


    private static String encryptAes(SAECipherType citype, SAECipherKey key, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
            byte[] plainBytes = plainText.getBytes();
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            return encryptedText;
        } catch (NoSuchPaddingException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (BadPaddingException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        }
    }

    private static String encryptRsa(SAECipherType citype, SAECipherKey key, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
            byte[] plainBytes = plainText.getBytes();
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            return encryptedText;
        } catch (NoSuchPaddingException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (BadPaddingException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new EncryptFailureException(e.getMessage(), e);
        }
    }

    public static String decrypt(SAECipherType citype, SAECipherKey key, String encryptedText) {
        String decrypted = null;
        switch (citype) {
            case AES_256:
                decrypted = decryptAes(SAECipherType.AES_256, key, encryptedText);
                break;
            case RSA_2048:
                decrypted = decryptRsa(SAECipherType.RSA_2048, key, encryptedText);
                break;
            default:
                break;
        }
        return decrypted;
    }

    public static String decrypt(SAECipherType citype, String key, String plainText) {
        try {
            SAECipherKey saeKey = null;
            switch (citype) {
                case AES_256:
                    byte[] decodedKey = Base64.getDecoder().decode(key);
                    SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");
                    saeKey = new SAECipherKey(secretKey, null, null);
                    break;
                case RSA_2048:
                    byte[] keyBytes = Base64.getDecoder().decode(key);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                    saeKey = new SAECipherKey(null, null, privateKey);
                    break;
                default:
                    break;
            }
            return decrypt(citype, saeKey, plainText);
        } catch (NoSuchAlgorithmException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (InvalidKeySpecException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        }
    }



    private static String decryptAes(SAECipherType citype, SAECipherKey key, String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey());
            byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
            byte[] plainBytes = cipher.doFinal(encryptedBytes);
            String plainText = new String(plainBytes);
            return plainText;
        } catch (NoSuchPaddingException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (BadPaddingException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        }
    }

    private static String decryptRsa(SAECipherType citype, SAECipherKey key, String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key.getPrivateKey());
            byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            return decryptedText;
        } catch (NoSuchPaddingException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (BadPaddingException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new DecryptFailureException(e.getMessage(), e);
        }
    }

    public static String sign(SAECipherKey myKey, String msg) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(myKey.getPrivateKey());
            signature.update(msg.getBytes());
            byte[] signedBytes = signature.sign();
            String signedText = Base64.getEncoder().encodeToString(signedBytes);
            return signedText;
        } catch (NoSuchAlgorithmException e) {
            throw new SAECipherException(e.getMessage(), e);
        } catch (SignatureException e) {
            throw new SAECipherException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new SAECipherException(e.getMessage(), e);
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
            return isVerified;
        } catch (NoSuchAlgorithmException e) {
            throw new SAECipherException(e.getMessage(), e);
        } catch (SignatureException e) {
            throw new SAECipherException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            throw new SAECipherException(e.getMessage(), e);
        }
    }
    

}
