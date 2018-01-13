package com.dexmohq.dexcrypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import static java.lang.Integer.rotateLeft;

/**
 * SHA-1 implementation according to pseudo code found at <a href="https://en.wikipedia.org/wiki/SHA-1">Wikipedia</a>
 */
public class Sha1 {

    // init variables
    int h0 = 0x67452301;
    int h1 = 0xEFCDAB89;
    int h2 = 0x98BADCFE;
    int h3 = 0x10325476;
    int h4 = 0xC3D2E1F0;

    private byte[] buffer = new byte[0];
    private long messageLength = 0;

    public void update(byte[] message) {
        // strip remainder into a buffer
        final int chunks = message.length / 64;
        buffer = new byte[message.length - chunks * 64];
        System.arraycopy(message, chunks * 64, buffer, 0, buffer.length);
        // update the chunks in the message
        updateInternal(message);
        messageLength += chunks * 512L;
    }

    private void updateInternal(byte[] chunks) {
        for (int chunk = 0; chunk < chunks.length / 64; chunk++) {
            final int[] words = new int[80];
            // break chunk into 32 bit words
            for (int i = 0; i < 16; i++) {
                words[i] = ByteBuffer.allocate(Integer.BYTES).put(chunks, chunk * 64 + i * 4, 4).getInt(0);
            }
            // extend into 80 words total
            for (int i = 16; i < 80; i++) {
                words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            }
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            for (int i = 0; i < 80; i++) {
                int f, k;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                int temp = rotateLeft(a, 5) + f + e + k + words[i];
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = temp;
            }
            // add this chunks hash to result so far
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }
    }

    private void updateBuffer() {
        // pad the message
        int ml = buffer.length;
        final byte[] chunk = Arrays.copyOf(buffer, 64);
        chunk[ml] = (byte) 0x80;
        messageLength += ml * 8L;
        if (ml + 9 > 64) {
            updateInternal(chunk);
            final byte[] last = new byte[64];
            final byte[] mlBits = ByteBuffer.allocate(Long.BYTES).putLong(messageLength).array();
            System.arraycopy(mlBits, 0, last, 64 - 8, 8);
            updateInternal(last);
        } else {
            final byte[] mlBits = ByteBuffer.allocate(Long.BYTES).putLong(messageLength).array();
            System.arraycopy(mlBits, 0, chunk, 64 - 8, 8);
            updateInternal(chunk);
        }
    }

    public byte[] digest() {
        updateBuffer();
        // final 160-bit hash value
        final ByteBuffer hhBuffer = ByteBuffer.allocate(20);
        hhBuffer.putInt(h0);
        hhBuffer.putInt(h1);
        hhBuffer.putInt(h2);
        hhBuffer.putInt(h3);
        hhBuffer.putInt(h4);
        return hhBuffer.array();
    }

    public static byte[] hash(byte[] message) {
        final Sha1 sha1 = new Sha1();
        sha1.update(message);
        return sha1.digest();
    }

    public static void main(String[] args) throws Exception {
        final Base64.Encoder base64 = Base64.getEncoder();
        final Random random = new Random();
        final byte[] part1 = new byte[129];
        random.nextBytes(part1);

//        final byte[] part2 = new byte[721];
//        random.nextBytes(part2);
//
//        final byte[] complete = new byte[part1.length + part2.length];
//        System.arraycopy(part1, 0, complete, 0, part1.length);
//        System.arraycopy(part2, 0, complete, part1.length, part2.length);
//
//        final MessageDigest partialMd = MessageDigest.getInstance("SHA1");
//
//        partialMd.update(part1);
//        partialMd.update(part2);
//        System.out.println(base64.encodeToString(partialMd.digest()));
//        final MessageDigest completeMd = MessageDigest.getInstance("SHA1");
//
//        System.out.println(base64.encodeToString(completeMd.digest(complete)));

        final MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(part1);
        final byte[] digestHash = md.digest();

        System.out.println(base64.encodeToString(digestHash));
        System.out.println(base64.encodeToString(hash(part1)));
    }

}
