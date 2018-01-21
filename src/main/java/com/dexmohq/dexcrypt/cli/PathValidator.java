package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;

public class PathValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        if (!new File(value).exists()) {
            throw new ParameterException("The specified path does not exist.");
        }
    }
}
