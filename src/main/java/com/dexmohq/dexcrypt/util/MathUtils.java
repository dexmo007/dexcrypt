package com.dexmohq.dexcrypt.util;

public class MathUtils {

    public static boolean isPowerOfTwo(int n) {
        return (n & (n - 1)) == 0;
    }


}
