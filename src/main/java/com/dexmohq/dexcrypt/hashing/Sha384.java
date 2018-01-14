package com.dexmohq.dexcrypt.hashing;

import com.dexmohq.dexcrypt.Sha512;

import java.nio.ByteBuffer;

public class Sha384 extends Sha512 {

    public Sha384() {
        h0 = 0xcbbb9d5dc1059ed8L;
        h1 = 0x629a292a367cd507L;
        h2 = 0x9159015a3070dd17L;
        h3 = 0x152fecd8f70e5939L;
        h4 = 0x67332667ffc00b31L;
        h5 = 0x8eb44a8768581511L;
        h6 = 0xdb0c2e0d64f98fa7L;
        h7 = 0xdb0c2e0d64f98fa7L;
    }

    /**
     * omits the last two 64-bit hash values
     * @return SHA-384 hash
     */
    @Override
    protected byte[] digestInternal() {
        final ByteBuffer hash = ByteBuffer.allocate(6 * Long.BYTES);
        hash.putLong(h0);
        hash.putLong(h1);
        hash.putLong(h2);
        hash.putLong(h3);
        hash.putLong(h4);
        hash.putLong(h5);
        return hash.array();
    }
}
