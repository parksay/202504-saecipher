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
    public void cipherTest() throws NoSuchPaddingException, NoSuchAlgorithmException {
        //
        Cipher cipher = Cipher.getInstance("AES");
        String myKey = SAECipher.getKey(SAECipher.TYPE_AES_256);
        String plainText = "plainText";
        String encrypted = SAECipher.encrypt(SAECipher.TYPE_AES_256, myKey, plainText);
        String decrypted = SAECipher.decrypt(SAECipher.TYPE_AES_256, myKey, plainText);
        //
        SAECipher sc2 = SAECipher.getInstance(SAECipher.TYPE_AES);
        sc2.setKey(myKey);
        String decrypted = sc.decrypt(encrypted);
    }

}
