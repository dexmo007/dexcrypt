package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.ParameterException;
import com.dexmohq.dexcrypt.util.MathUtils;

public class BufferSizeValidator implements IValueValidator<Integer> {
    @Override
    public void validate(String name, Integer value) throws ParameterException {
        if (value <= 0) {
            throw new ParameterException("The buffer size must be bigger than zero.");
        }
        //todo check for too big number, get available heap space?
//        Runtime.getRuntime().freeMemory()
//        Runtime.getRuntime().maxMemory()
//        Runtime.getRuntime().totalMemory()
        if (!MathUtils.isPowerOfTwo(value)) {
            System.out.println("[WARN] We recommend a buffer size that is a power of two: 512, 1024, 2048, 4096, 8192, ...");
        }
    }
}
