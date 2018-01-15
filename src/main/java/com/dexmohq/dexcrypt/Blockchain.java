package com.dexmohq.dexcrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Blockchain {

    private int mineSeq(String data) {
        int nonce = 0;// treated as unsigned
        final MessageDigest md = newSha256Digest();
        final byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        final byte[] input = new byte[bytes.length + Integer.BYTES];
        System.arraycopy(bytes, 0, input, 4, bytes.length);
        do {
            input[0] = (byte) (nonce & 0xff);
            input[1] = (byte) ((nonce >>> 4) & 0xff);
            input[2] = (byte) ((nonce >>> 8) & 0xff);
            input[3] = (byte) ((nonce >>> 12) & 0xff);
            final byte[] hashBytes = md.digest(input);
            if (hashBytes[0] == 0 && hashBytes[1] == 0) {
                return nonce;
            }
            md.reset();
            nonce++;
        } while (nonce != 0);//while nonce reaches zero again due to numeric overflow -> we tested all 4-byte ints
        throw new IllegalStateException("No nonce found");
    }

    private int mineParallel(String data) {
        return mineParallel(data, Runtime.getRuntime().availableProcessors());
    }

    private int mineParallel(String data, int parallelism) {
        final ExecutorService es = Executors.newFixedThreadPool(parallelism);
        final ArrayList<Callable<Integer>> tasks = new ArrayList<>();
        final byte[] bytes = data.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < parallelism; i++) {
            final int starting = i;
            tasks.add(() -> {
                final byte[] input = new byte[Integer.BYTES + bytes.length];//thread local data array that can be prefixed by the 4 nonce bytes
                System.arraycopy(bytes, 0, input, Integer.BYTES, bytes.length);
                final MessageDigest md = newSha256Digest();// thread local message digest
                int nonce = starting;
                do {
                    input[0] = (byte) (nonce & 0xff);
                    input[1] = (byte) ((nonce >>> 4) & 0xff);
                    input[2] = (byte) ((nonce >>> 8) & 0xff);
                    input[3] = (byte) ((nonce >>> 12) & 0xff);
                    final byte[] hashBytes = md.digest(input);
                    if (hashBytes[0] == 0 && hashBytes[1] == 0) {
                        return nonce;
                    }
                    md.reset();
                    nonce += parallelism;
                } while (nonce != starting && !es.isShutdown());

                throw new IllegalStateException("No nonce found");
            });
        }
        try {
            final int nonce = es.invokeAny(tasks);
            es.shutdownNow();
            return nonce;
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        } finally {
            es.shutdownNow();
        }
    }

    private MessageDigest newSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError(e);
        }
    }


}
