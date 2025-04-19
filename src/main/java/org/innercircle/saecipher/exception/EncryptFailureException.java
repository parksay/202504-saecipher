package org.innercircle.saecipher.exception;

public class EncryptFailureException extends ClassCastException{

    public EncryptFailureException(String msg, Throwable e) {
        super(msg, e);
    }

}
