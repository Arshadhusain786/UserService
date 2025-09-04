package com.scaler.userService.Exceptions;

public class WrongPasswordException extends RuntimeException
{
    public WrongPasswordException(String message) {
        super(message);
    }
}
