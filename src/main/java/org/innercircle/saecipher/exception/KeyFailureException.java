package org.innercircle.saecipher.exception;

public class KeyFailureException extends SAECipherException {
    public KeyFailureException(String msg, Throwable e) {
        super(msg, e);
    }
}
