package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.IStringConverter;

public class PasswordConverter implements IStringConverter<char[]> {
    @Override
    public char[] convert(String value) {
        return value.toCharArray();
    }
}
