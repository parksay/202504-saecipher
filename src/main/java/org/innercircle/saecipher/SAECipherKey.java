package org.innercircle.saecipher;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SAECipherKey {

    private final SecretKey secretKey;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;


    public SAECipherKey(SecretKey secretKey, PublicKey publicKey, PrivateKey privateKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public String toString() {
        return String.valueOf(this.hashCode());
    }
}
