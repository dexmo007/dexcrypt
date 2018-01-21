package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.ParameterException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashAlgorithmValidator implements IValueValidator<String> {

    public static final String ERROR_MESSAGE = "Invalid hashing algorithm (you can list all with the option -l or --list-algorithms)";

    @Override
    public void validate(String name, String value) throws ParameterException {
        try {
            MessageDigest.getInstance(value);
        } catch (NoSuchAlgorithmException e) {
            throw new ParameterException(ERROR_MESSAGE);
        }
    }
}
