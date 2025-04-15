import org.innercircle.saecipher.SAECipher;
import org.innercircle.saecipher.SAECipherKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
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
        SAECipherKey myKey = SAECipher.generateKey(SAECipher.TYPE_AES_256);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipher.TYPE_AES_256, myKey, plainText);
        logger.info("encrypted ====== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipher.TYPE_AES_256, myKey, encrypted);
        logger.info("decrypted ====== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }



    @Test
    public void rsaTest(){
        //
        SAECipherKey myKey = SAECipher.generateKey(SAECipher.TYPE_RSA_2048);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipher.TYPE_RSA_2048, myKey, plainText);
        logger.info("encrypted ========== ");
        logger.info(encrypted);
        String decrypted = SAECipher.decrypt(SAECipher.TYPE_RSA_2048, myKey, encrypted);
        logger.info("decrypted ========== ");
        logger.info(decrypted);
        //
        Assertions.assertNotEquals(plainText, encrypted);
        Assertions.assertTrue(plainText.length() < encrypted.length());
        Assertions.assertEquals(plainText, decrypted);
    }

    @Test
    public void signTest() {
        SAECipherKey myKey = SAECipher.generateKey(SAECipher.TYPE_RSA_2048);
        String plainText = "plainText";
        String signed = SAECipher.sign(myKey, plainText);
        boolean isVerified = SAECipher.verify(myKey, plainText, signed);
        logger.info("isVerified ========== " + isVerified);
        Assertions.assertTrue(isVerified);
    }


    @Test
    public void cipherHelpTest() throws NoSuchPaddingException, NoSuchAlgorithmException {
        //
        String[] strings = {"hello", "world"};
        String first = strings[0];
        String second = strings[1];
    }
}
