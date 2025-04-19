import org.innercircle.saecipher.SAECipher;
import org.innercircle.saecipher.SAECipherKey;
import org.innercircle.saecipher.SAECipherType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

public class CipherTest {

    private static final Logger logger = Logger.getLogger(CipherTest.class.getName());

    @Test
    public void runTest() {
        logger.info("hello");
        return;
    }


    @Test
    public void aesTest() {
        //
        SAECipherKey myKey = SAECipher.generateKey(SAECipherType.AES_256);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipherType.AES_256, myKey, plainText);
        logger.info("encrypted ====== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipherType.AES_256, myKey, encrypted);
        logger.info("decrypted ====== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }



    @Test
    public void rsaTest() {
        //
        SAECipherKey myKey = SAECipher.generateKey(SAECipherType.RSA_2048);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipherType.RSA_2048, myKey, plainText);
        logger.info("encrypted ========== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipherType.RSA_2048, myKey, encrypted);
        logger.info("decrypted ========== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }

    @Test
    public void signTest() {
        SAECipherKey myKey = SAECipher.generateKey(SAECipherType.RSA_2048);
        String plainText = "plainText";
        String signed = SAECipher.sign(myKey, plainText);
        boolean isVerified = SAECipher.verify(myKey, plainText, signed);
        logger.info("isVerified ========== " + isVerified);
        Assertions.assertTrue(isVerified);
    }

    @Test
    public void aesTestOl() {
        //
        SAECipherKey myKey = SAECipher.generateKey(SAECipherType.AES_256);
        String strKey = Base64.getEncoder().encodeToString(myKey.getSecretKey().getEncoded());
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipherType.AES_256, myKey, plainText);
        logger.info("encrypted ====== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipherType.AES_256, strKey, encrypted);
        logger.info("decrypted ====== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }




    @Test
    public void rsaTestOl() {
        //
        SAECipherKey myKey = SAECipher.generateKey(SAECipherType.RSA_2048);
        String strPriKey = Base64.getEncoder().encodeToString(myKey.getPrivateKey().getEncoded());
        String strPubKey = Base64.getEncoder().encodeToString(myKey.getPublicKey().getEncoded());
        logger.info("strPriKey ===== ");
        logger.info(strPriKey);
        logger.info("strPubKey ===== ");
        logger.info(strPubKey);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipherType.RSA_2048, strPubKey, plainText);
        logger.info("encrypted ========== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipherType.RSA_2048, strPriKey, encrypted);
        logger.info("decrypted ========== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }


    @Test
    public void cipherHelpTest() throws NoSuchAlgorithmException {
        //
        String[] strings = {"hello", "world"};
        String first = strings[0];
        String second = strings[1];
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        logger.info("secretKey");
        logger.info(secretKey.toString());
    }
}
