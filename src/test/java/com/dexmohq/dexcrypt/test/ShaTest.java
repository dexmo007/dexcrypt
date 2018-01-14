package com.dexmohq.dexcrypt.test;

import com.dexmohq.dexcrypt.hashing.*;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runners.Parameterized;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Random;

public class ShaTest {

    @Test
    public void testSha1Incremental() throws Exception {
        testIncremental(new Sha1(), "SHA1", 10_000);
    }

    @Test
    public void testSha1Large() throws Exception {
        testLarge(new Sha1(), "SHA1", 2147, 1000);
    }

    @Test
    public void testSha256Incremental() throws Exception {
        testIncremental(new Sha256(), "SHA-256", 10_001);
    }

    @Test
    public void testSha256Large() throws Exception {
        testLarge(new Sha256(), "SHA-256", 2184, 1001);
    }

    @Test
    public void testSha512Incremental() throws Exception {
        testIncremental(new Sha512(), "SHA-512", 10_000);
    }

    @Test
    public void testSha512Large() throws Exception {
        testLarge(new Sha512(), "SHA-512", 4752, 1000);
    }

    @Test
    public void testSha384Incremental() throws Exception {
        testIncremental(new Sha384(), "SHA-384", 10_000);
    }

    @Test
    public void testSha384Large() throws Exception {
        testLarge(new Sha384(), "SHA-384", 4281, 1000);
    }

    @Test
    public void testSha224Incremental() throws Exception {
        testIncremental(new Sha224(), "SHA-224", 10_000);
    }

    @Test
    public void testSha224Large() throws Exception {
        testLarge(new Sha224(), "SHA-224", 3127, 1000);
    }

    /*
    TESTING LOGIC
     */

    private void testLarge(ShaAlgorithm sha, String messageDigest, int maxBufferSize, int iterations) throws NoSuchAlgorithmException {
        final Random random = new Random();
        byte[] buffer;
        final MessageDigest md = MessageDigest.getInstance(messageDigest);
        for (int i = 0; i < iterations; i++) {
            buffer = new byte[random.nextInt(maxBufferSize)];
            random.nextBytes(buffer);
            md.update(buffer);
            sha.update(buffer);
        }
        Assert.assertArrayEquals(md.digest(), sha.digest());
    }

    private void testIncremental(ShaAlgorithm sha, String messageDigest, int limit) throws NoSuchAlgorithmException {
        final Random random = new Random();
        for (int i = 0; i < limit; i++) {
            final byte[] bytes = new byte[i];
            random.nextBytes(bytes);
            final byte[] expected = MessageDigest.getInstance(messageDigest).digest(bytes);
            final byte[] actual = sha.hash(bytes);
            Assert.assertArrayEquals("did not match at size " + i, expected, actual);
        }
    }
}
