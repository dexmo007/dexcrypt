package com.dexmohq.dexcrypt;

import java.security.MessageDigest;

public class Blockchain {

    public long mineSeq(byte[] data) {
        long nonce = 0L;
        while (nonce != -1) {
//            MessageDigest.getInstance("SHA-256").digest(data)
            nonce++;
        }
        return 0;
    }


}
