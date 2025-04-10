import org.innercircle.saecipher.SAECipher;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class CipherTest {


    @Test
    public void runTest() {
        System.out.println("hello");
        return;
    }


    @Test
    public void cipherAESTest() throws NoSuchPaddingException, NoSuchAlgorithmException {
        //
        Cipher cipher = Cipher.getInstance("AES");
        SAECipher.SAECipherKey myKey = SAECipher.generateKey(SAECipher.TYPE_AES_256);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipher.TYPE_AES_256, myKey, plainText);
        String decrypted = SAECipher.decrypt(SAECipher.TYPE_AES_256, myKey, encrypted);
    }



    @Test
    public void cipherRSATest() throws NoSuchPaddingException, NoSuchAlgorithmException {
        //
        SAECipher.SAECipherKey myKeyPair = SAECipher.generateKey(SAECipher.TYPE_RSA_2048);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipher.TYPE_RSA_2048, myKeyPair.getPublicKey(), plainText);
        String decrypted = SAECipher.decrypt(SAECipher.TYPE_RSA_2048, myKeyPair.getSecretKey(), encrypted);
    }


    @Test
    public void cipherHelpTest() throws NoSuchPaddingException, NoSuchAlgorithmException {
        //
        String[] strings = {"hello", "world"};
        String first = strings[0];
        String second = strings[1];
    }
}
