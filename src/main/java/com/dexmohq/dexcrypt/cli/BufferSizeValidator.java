package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.IValueValidator;
import com.beust.jcommander.ParameterException;
import com.dexmohq.dexcrypt.util.MathUtils;

public class BufferSizeValidator implements IValueValidator<Integer> {

    public static final String NOT_A_POWER_OF_TWO_WARNING_MESSAGE = "[WARN] We recommend a buffer size that is a power of two: 512, 1024, 2048, 4096, 8192, ...";
    public static final String INVALID_BUFFER_SIZE_ERROR_MESSAGE = "The buffer size must be bigger than zero.";

    @Override
    public void validate(String name, Integer value) throws ParameterException {
        if (value <= 0) {
            throw new ParameterException(INVALID_BUFFER_SIZE_ERROR_MESSAGE);
        }
        //todo check for too big number, get available heap space?
//        Runtime.getRuntime().freeMemory()
//        Runtime.getRuntime().maxMemory()
//        Runtime.getRuntime().totalMemory()
        if (!MathUtils.isPowerOfTwo(value)) {
            System.out.println(NOT_A_POWER_OF_TWO_WARNING_MESSAGE);
        }
    }
}
