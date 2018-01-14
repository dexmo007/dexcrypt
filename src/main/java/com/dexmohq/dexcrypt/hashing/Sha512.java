package com.dexmohq.dexcrypt.hashing;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

import static java.lang.Long.rotateRight;

public class Sha512 extends ShaAlgorithm {//todo fix big integer as counter, as 16-byte value

    public static final int ROUNDS = 80;

    protected long h0 = 0x6a09e667f3bcc908L;
    protected long h1 = 0xbb67ae8584caa73bL;
    protected long h2 = 0x3c6ef372fe94f82bL;
    protected long h3 = 0xa54ff53a5f1d36f1L;
    protected long h4 = 0x510e527fade682d1L;
    protected long h5 = 0x9b05688c2b3e6c1fL;
    protected long h6 = 0x1f83d9abfb41bd6bL;
    protected long h7 = 0x5be0cd19137e2179L;

    protected BigInteger bits = BigInteger.ZERO;

    protected static final long[] k = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L,
            0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL,
            0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
            0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL,
            0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
            0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL,
            0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
            0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L,
            0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L,
            0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL,
            0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L,
            0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
            0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    public Sha512() {
        // SHA-512 uses 1024 bit chunks
        super(128);
        messageLengthBytes = 16;//128-bit uint for length
    }

    @Override
    protected void updateMessageLengthBits(long messageBits) {
        bits = bits.add(BigInteger.valueOf(messageBits));
    }

    @Override
    protected void updateInternal(byte[] chunks) {
        for (int chunk = 0; chunk < chunks.length / chunkSize; chunk++) {
            final long[] w = new long[ROUNDS];
            for (int i = 0; i < 16; i++) {
                w[i] = ByteBuffer.allocate(Long.BYTES).put(chunks, chunk * chunkSize + i * Long.BYTES, Long.BYTES).getLong(0);
            }
            for (int i = 16; i < ROUNDS; i++) {
                final long w15 = w[i - 15];
                final long s0 = rotateRight(w15, 1) ^ rotateRight(w15, 8) ^ (w15 >>> 7);
                final long w2 = w[i - 2];
                final long s1 = rotateRight(w2, 19) ^ rotateRight(w2, 61) ^ (w2 >>> 6);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            long a = h0;
            long b = h1;
            long c = h2;
            long d = h3;
            long e = h4;
            long f = h5;
            long g = h6;
            long h = h7;
            for (int i = 0; i < ROUNDS; i++) {
                long s1 = rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41);
                long ch = (e & f) ^ ((~e) & g);
                long temp1 = h + s1 + ch + k[i] + w[i];
                long s0 = rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39);
                long maj = (a & b) ^ (a & c) ^ (b & c);
                long temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
    }

    @Override
    protected byte[] getMessageLengthBytes() {
        return bigIntToByteArray(bits, 16);
    }

    @Override
    protected byte[] digestInternal() {
        final ByteBuffer hash = ByteBuffer.allocate(Long.BYTES * 8);
        hash.putLong(h0);
        hash.putLong(h1);
        hash.putLong(h2);
        hash.putLong(h3);
        hash.putLong(h4);
        hash.putLong(h5);
        hash.putLong(h6);
        hash.putLong(h7);
        return hash.array();
    }

    @Override
    protected ShaAlgorithm clone() throws CloneNotSupportedException {
        return new Sha512();
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] bigIntToByteArray(BigInteger bigInteger, int maxBytes) {
        final byte[] bytes = bigInteger.toByteArray();
        if (bytes.length == maxBytes) {
            return bytes;
        } else if (bytes.length < maxBytes) {
            final byte[] res = new byte[maxBytes];
            System.arraycopy(bytes, 0, res, res.length - bytes.length, bytes.length);
            return res;
        }
        final byte[] res = new byte[maxBytes];
        System.arraycopy(bytes, bytes.length - res.length, res, 0, res.length);
        return res;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Base64.Encoder base64 = Base64.getEncoder();

        final byte[] message = new byte[112];
        new Random().nextBytes(message);
        System.out.println(base64.encodeToString(MessageDigest.getInstance("SHA-512").digest(message)));
        System.out.println(base64.encodeToString(new Sha512().digest(message)));
    }

}