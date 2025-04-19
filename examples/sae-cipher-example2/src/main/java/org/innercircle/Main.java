package org.innercircle;

import org.innercircle.saecipher.SAECipher;
import org.innercircle.saecipher.SAECipherKey;
import org.innercircle.saecipher.SAECipherType;

import java.util.logging.Logger;

public class Main {
    private static Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        String msg = "Hello world!";

        SAECipherKey keyRSA = SAECipher.generateKey(SAECipherType.RSA_2048);
        String signed =  SAECipher.sign(keyRSA, msg);
        boolean isVerified = SAECipher.verify(keyRSA, msg, signed);
        logger.info("isVerified ==");
        logger.info(""+isVerified);
    }
}