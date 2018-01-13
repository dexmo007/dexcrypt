package com.dexmohq.dexcrypt.test;

import com.dexmohq.dexcrypt.Sha1;
import org.junit.Assert;
import org.junit.Test;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

public class Sha1Test {

    @Test
    public void testIncremental() throws Exception {
        final Random random = new Random();
        for (int i = 0; i < 10000; i++) {
            final byte[] bytes = new byte[i];
            random.nextBytes(bytes);
            final byte[] expected = MessageDigest.getInstance("SHA1").digest(bytes);
            final byte[] actual = Sha1.hash(bytes);
            Assert.assertArrayEquals("did not match at size " + i, expected, actual);
        }
    }

    @Test
    public void testLarge() throws Exception {
        final Random random = new Random();
        final byte[] buffer = new byte[1024];// megabyte buffer
        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final Sha1 sha1 = new Sha1();
        for (int i = 0; i < 1000; i++) {
            random.nextBytes(buffer);
            md.update(buffer);
            sha1.update(buffer);
        }
        Assert.assertArrayEquals(md.digest(), sha1.digest());
    }
}
