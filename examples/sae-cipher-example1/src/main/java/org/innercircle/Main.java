package org.innercircle;

import org.innercircle.saecipher.SAECipher;
import org.innercircle.saecipher.SAECipherKey;
import org.innercircle.saecipher.SAECipherType;

import java.util.Base64;
import java.util.logging.Logger;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        String resiNum = "123456-1234567";
        // encrypt
        SAECipherKey keyRSA = SAECipher.generateKey(SAECipherType.RSA_2048);
        SAECipherKey keyAES = SAECipher.generateKey(SAECipherType.AES_256);
        String strKeyAes = Base64.getEncoder().encodeToString(keyAES.getSecretKey().getEncoded());
        //
        String encryptedResiNum = SAECipher.encrypt(SAECipherType.AES_256, keyAES, resiNum);
        String encryptedKeyAes = SAECipher.encrypt(SAECipherType.RSA_2048, keyRSA, strKeyAes);
        //
        UserService userService = new UserService();
        userService.save(encryptedResiNum, encryptedKeyAes);
        //
        // decrypt
        String decryptedKeyAes = SAECipher.decrypt(SAECipherType.RSA_2048, keyRSA, encryptedKeyAes);
        String decryptedResiNum = SAECipher.decrypt(SAECipherType.AES_256, decryptedKeyAes, encryptedResiNum);

        logger.info("resiNum === ");
        logger.info(resiNum);
        logger.info("encryptedResiNum === ");
        logger.info(encryptedResiNum);
        logger.info("decryptedResiNum === ");
        logger.info(decryptedResiNum);

    }
}