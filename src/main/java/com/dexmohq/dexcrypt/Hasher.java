package com.dexmohq.dexcrypt;

import com.google.common.io.BaseEncoding;
import lombok.AllArgsConstructor;
import lombok.Cleanup;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import static com.dexmohq.dexcrypt.util.FileUtils.EOF;

@AllArgsConstructor
public class Hasher {

    private final String algorithm;

    private final int bufferSize;

    private final String path;

    private final String output;

    public void hash() {
        try {
            hashInternal();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void hashInternal() throws IOException {
        final MessageDigest md = getDigest();
        @Cleanup final BufferedInputStream in = new BufferedInputStream(new FileInputStream(new File(path)));
        int read;
        final byte[] buffer = new byte[bufferSize];
        while ((read = in.read(buffer)) != EOF) {
            md.update(buffer, 0, read);
        }
        final byte[] digest = md.digest();
        final String encoded = BaseEncoding.base16().encode(digest);
        if (output == null) {
            System.out.println(encoded);
        } else {
            Files.write(Paths.get(new File(output).toURI()), Collections.singleton(encoded));//todo override flag
        }
    }

    private MessageDigest getDigest() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
