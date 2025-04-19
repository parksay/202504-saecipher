package org.innercircle.saecipher.exception;

public class DecryptFailureException extends SAECipherException {
    public DecryptFailureException(String msg, Throwable e) {
        super(msg, e);
    }
}
