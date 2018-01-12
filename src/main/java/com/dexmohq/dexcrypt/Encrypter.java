package com.dexmohq.dexcrypt;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Encrypter {

    private static byte[] randomIv(int size) throws NoSuchAlgorithmException {
        final byte[] iv = new byte[size];
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.nextBytes(iv);
        return iv;
    }

    public static Key getKey(String password) {
        final HashCode hashed = Hashing.sha256().hashString(password, StandardCharsets.UTF_8);
        final byte[] key = new byte[16];
        hashed.writeBytesTo(key, 0, 16);
        return new SecretKeySpec(key, "AES");
    }

    private static final long DXP_MAGIC = 0x08154711;
    private static final byte[] DXP_MAGIC_BYTES = ByteBuffer.allocate(Long.BYTES).putLong(DXP_MAGIC).array();

    private static void encryptFile(String fileName, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        final InputStream in = new FileInputStream(new File(fileName));
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final byte[] iv = randomIv(16);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(password), new IvParameterSpec(iv));

        final FileOutputStream fos = new FileOutputStream(
                new File(fileName + ENCRYPTED_FILE_EXTENSION));
        fos.write(DXP_MAGIC_BYTES);
        fos.write(iv);

        final OutputStream out = new GZIPOutputStream(
                new CipherOutputStream(
                        fos, cipher));
        final byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        out.close();
    }

    public static int BUFFER_SIZE = 4096;

    private static byte[] newBuffer() {
        return new byte[BUFFER_SIZE];
    }

    private static InputStream zipFolder(String fullPath) throws IOException {
        final File dir = new File(fullPath);
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException("not a dir");
        }

        final String zipFile = dir.getAbsolutePath() + ".zip";
        final ZipOutputStream out = new ZipOutputStream(new FileOutputStream(new File(zipFile)));//todo prevent overwrite

        int read;
        final byte[] buffer = new byte[BUFFER_SIZE];


        final File[] files = dir.listFiles();
        for (File file : files) {
            if (file.isDirectory()) {
                continue;//todo optional inclusion of subdirs
            }
            final ZipEntry zipEntry = new ZipEntry(FileUtils.getPathRelativeTo(file, dir));
            out.putNextEntry(zipEntry);
            final FileInputStream fileInput = new FileInputStream(file);
            while ((read = fileInput.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            fileInput.close();
            out.closeEntry();
        }

        out.close();

        return new FileInputStream(new File(zipFile));
    }

    private static void encryptFolder(String folder, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final byte[] iv = randomIv(16);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(password), new IvParameterSpec(iv));

        final FileOutputStream fos = new FileOutputStream(
                new File(folder + ENCRYPTED_FILE_EXTENSION));
        fos.write(DXP_MAGIC_BYTES);
        fos.write(iv);

        final InputStream in = zipFolder(folder);

        final OutputStream out = new GZIPOutputStream(
                new CipherOutputStream(
                        fos, cipher));
        final byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        out.close();

//        Files.delete();
    }

    private static void decryptFile(String fileName, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        final FileInputStream fileInput = new FileInputStream(new File(fileName));

        // check magic byte start
        final byte[] magicBytes = new byte[DXP_MAGIC_BYTES.length];
        if (fileInput.read(magicBytes) != DXP_MAGIC_BYTES.length) {
            throw new DecryptionException("magic bytes could not be retrieved");
        }
        if (ByteBuffer.wrap(magicBytes).getLong() != DXP_MAGIC) {
            throw new DecryptionException("magic number does not match");
        }
        // retrieve IV
        final byte[] iv = new byte[16];
        if (fileInput.read(iv) != 16) {
            throw new DecryptionException("iv could not be read");
        }


        final OutputStream out = new FileOutputStream(new File(FileUtils.getFinalName(fileName)));
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, getKey(password), new IvParameterSpec(iv));

        final InputStream in = new GZIPInputStream(new CipherInputStream(fileInput, cipher));
        final byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        out.close();
    }

    private static final String ENCRYPTED_FILE_EXTENSION = ".dxp";

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        String fileName = "D:\\dexcrypttest\\files";

        zipFolder(fileName);

//        final String password = "supersecret";
//        encryptFile(fileName, password);
//        decryptFile(fileName + ".dxp", password);

    }


}
