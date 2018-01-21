package com.dexmohq.dexcrypt;

import com.dexmohq.dexcrypt.util.FileUtils;
import lombok.Cleanup;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

import static com.dexmohq.dexcrypt.util.FileUtils.EOF;

@RequiredArgsConstructor
public class Encrypter {

    public static final int DEFAULT_BUFFER_SIZE = 4096;
    private static final String ENCRYPTED_FILE_EXTENSION = ".dxp";
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY_SPEC = "PBKDF2WithHmacSHA1";
    private static final int ITERATIONS = 65824;
    private static final int SALT_BYTES = 16;
    private static final int AUTH_KEY_BYTES = 8;
    private static final int AES_KEY_LENGTH = 256;
    private static final String SECRET_KEY_SPEC = "AES";
    private static final int IV_BYTES = 16;

    private final int bufferSize;
    private final char[] password;
    private final String path;
    private final String output;
    private final boolean recursive;

    @SneakyThrows
    private static byte[] generateSalt(int size) {
        final SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] iv = new byte[size];
        random.nextBytes(iv);
        return iv;
    }

    @SneakyThrows
    private static Key[] generateKey(char[] password, byte[] salt) {
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_FACTORY_SPEC);
        final PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, AES_KEY_LENGTH);
        final SecretKey secretKey = keyFactory.generateSecret(keySpec);

        final byte[] keyBytes = secretKey.getEncoded();
        final SecretKeySpec authKey = new SecretKeySpec(
                Arrays.copyOfRange(keyBytes, 0, AUTH_KEY_BYTES), SECRET_KEY_SPEC);
        final SecretKeySpec encryptionKey = new SecretKeySpec(
                Arrays.copyOfRange(keyBytes, AUTH_KEY_BYTES, keyBytes.length), SECRET_KEY_SPEC);
        return new Key[]{authKey, encryptionKey};
    }

//    private static final byte[] DXP_MAGIC_BYTES =
//            BaseEncoding.base16().decode("E86AABD1CA6F791AED05D760F2E055FB58F6A193AF8F89029685272C717507B9");

//    private static void encryptFile(String fileName, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
//        final InputStream in = new FileInputStream(new File(fileName));
//        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        final byte[] iv = generateSalt(16);
//        cipher.init(Cipher.ENCRYPT_MODE, getKey(password), new IvParameterSpec(iv));
//
//        final FileOutputStream fos = new FileOutputStream(
//                new File(fileName + ENCRYPTED_FILE_EXTENSION));
//        fos.write(DXP_MAGIC_BYTES);
//        fos.write(iv);
//
//        final OutputStream out = new GZIPOutputStream(
//                new CipherOutputStream(
//                        fos, cipher));
//        final byte[] buffer = new byte[1024];
//        int read;
//        while ((read = in.read(buffer)) >= 0) {
//            out.write(buffer, 0, read);
//        }
//        out.close();
//    }

//    private static void decryptFile(String fileName, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
//
//        final FileInputStream fileInput = new FileInputStream(new File(fileName));
//
//        // check magic byte start
//        final byte[] magicBytes = new byte[DXP_MAGIC_BYTES.length];
//        if (fileInput.read(magicBytes) != DXP_MAGIC_BYTES.length) {
//            throw new DecryptionException("magic bytes could not be retrieved");
//        }
//        if (ByteBuffer.wrap(magicBytes).getLong() != DXP_MAGIC) {
//            throw new DecryptionException("magic number does not match");
//        }
//        // retrieve IV
//        final byte[] iv = new byte[16];
//        if (fileInput.read(iv) != 16) {
//            throw new DecryptionException("iv could not be read");
//        }
//
//
//        final OutputStream out = new FileOutputStream(new File(FileUtils.getDecryptedName(fileName)));
//        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        cipher.init(Cipher.DECRYPT_MODE, getKey(password), new IvParameterSpec(iv));
//
//        final InputStream in = new GZIPInputStream(new CipherInputStream(fileInput, cipher));
//        final byte[] buffer = new byte[1024];
//        int read;
//        while ((read = in.read(buffer)) >= 0) {
//            out.write(buffer, 0, read);
//        }
//        out.close();
//    }

    public void encrypt() {
        if (new File(path).isDirectory()) {
            encryptDirectory();
            throw new UnsupportedOperationException();
        } else {
            encryptFile();
        }
    }

    public void decrypt() throws CorruptedFileException, InvalidPasswordException, InvalidKeyException {
        decryptFile();//todo directory, included unzip
    }

    @SneakyThrows
    private void encryptFile() {
        String output;
        if ((output = this.output) == null) {
            output = path + ENCRYPTED_FILE_EXTENSION;//todo more intelligent
        }

        final byte[] salt = generateSalt(SALT_BYTES);
        final Key[] keys = generateKey(password, salt);
        final Key authKey = keys[0];
        final Key encryptionKey = keys[1];
        final Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        final byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();//   todo or     cipher.getIV();


        final File file = new File(path);
        @Cleanup InputStream in = new BufferedInputStream(new FileInputStream(file));
        final FileOutputStream rawOut = new FileOutputStream(new File(output));
        @Cleanup final CipherOutputStream out = new CipherOutputStream(rawOut, cipher);

        rawOut.write(salt);
        rawOut.write(authKey.getEncoded());
        rawOut.write(iv);

        int read;
        final byte[] buffer = new byte[bufferSize];
        while ((read = in.read(buffer)) != EOF) {
            out.write(buffer, 0, read);
        }
    }

    @SneakyThrows
    private void encryptDirectory() {
//        String output;
//        if ((output = this.output) == null) {
//            output = path + ".zip" + ENCRYPTED_FILE_EXTENSION;//todo more intelligent
//        }
//        final Cipher cipher = Cipher.getInstance(algorithm);
//        cipher.init(Cipher.ENCRYPT_MODE, getKey());
//        final File directory = new File(path);//directory
//        final byte[] buffer = new byte[bufferSize];
//        final ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream(bufferSize);
//        final ZipOutputStream zipped = new ZipOutputStream(byteBuffer);
//        @Cleanup final CipherOutputStream out = new CipherOutputStream(new BufferedOutputStream(new FileOutputStream(new File(output))), cipher);
//        out.write(DXP_MAGIC_BYTES);
//        for (File file : Objects.requireNonNull(directory.listFiles())) {
//            if (file.isDirectory() && !recursive) {
//                continue;
//            }
//            final ZipEntry zipEntry = new ZipEntry(FileUtils.getPathRelativeTo(file, directory));
//            zipped.putNextEntry(zipEntry);
//            @Cleanup InputStream in = new BufferedInputStream(new FileInputStream(file));
//            int read;
//            while ((read = in.read(buffer)) != EOF) {
//                zipped.write(buffer, 0, read);
//                final byte[] zippedBytes = byteBuffer.toByteArray();
//                out.write(zippedBytes);
//                byteBuffer.reset();
//            }
//            zipped.closeEntry();
//        }
    }

    @SneakyThrows({NoSuchAlgorithmException.class, NoSuchPaddingException.class,
            IOException.class, InvalidAlgorithmParameterException.class})
    private void decryptFile() throws CorruptedFileException, InvalidPasswordException, InvalidKeyException {
        String output;
        if ((output = this.output) == null) {
            output = FileUtils.getDecryptedName(path);
        }
        final FileInputStream rawIn = new FileInputStream(new File(path));

        final Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
        final byte[] salt = new byte[SALT_BYTES];
        if (rawIn.read(salt) != SALT_BYTES) {
            throw new CorruptedFileException();
        }
        final Key[] keys = generateKey(password, salt);
        final Key authKey = keys[0];
        final Key encryptionKey = keys[1];
        final byte[] readAuth = new byte[AUTH_KEY_BYTES];
        if (rawIn.read(readAuth) != AUTH_KEY_BYTES) {
            throw new CorruptedFileException();
        }
        if (!Arrays.equals(authKey.getEncoded(), readAuth)) {
            throw new InvalidPasswordException();
        }
        final byte[] iv = new byte[IV_BYTES];
        if (rawIn.read(iv) != IV_BYTES) {
            throw new CorruptedFileException();
        }

        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
        InputStream in = new CipherInputStream(rawIn, cipher);

        @Cleanup final OutputStream out = new FileOutputStream(new File(output));
        final byte[] buffer = new byte[bufferSize];
        int read;
        while ((read = in.read(buffer)) != EOF) {
            out.write(buffer, 0, read);
        }
    }

    @SneakyThrows
    private void decryptDirectory() {
//        String output;
//        if ((output = this.output) == null) {
//            output = FileUtils.stripFileExtension(
//                    FileUtils.stripFileExtension(path, "dxp"), "zip");
//        }
//        final Cipher cipher = Cipher.getInstance(algorithm);
//        cipher.init(Cipher.DECRYPT_MODE, getKey());
//        try (InputStream rawInput = new CipherInputStream(new BufferedInputStream(new FileInputStream(new File(path))), cipher)) {
//            final byte[] magicBytes = new byte[DXP_MAGIC_BYTES.length];
//            // test magic bytes
//            if (rawInput.read(magicBytes) != DXP_MAGIC_BYTES.length || !Arrays.equals(DXP_MAGIC_BYTES, magicBytes)) {
//                throw new DecryptionException("Wrong password");
//            }
//            final ZipInputStream in = new ZipInputStream(rawInput);
//            ZipEntry entry;
//            int read;
//            final byte[] buffer = new byte[bufferSize];
//            while ((entry = in.getNextEntry()) != null) {
//                final File outFile = Paths.get(output, entry.getName()).toFile();
//                outFile.mkdirs();
//                final OutputStream out = new BufferedOutputStream(new FileOutputStream(outFile));
//
//                while ((read = in.read(buffer)) != EOF) {
//                    out.write(buffer, 0, read);
//                }
//                out.close();
//            }
//
//
//        } catch (EOFException e) {
//            // ignore
//        } catch (FileNotFoundException e) {
//            throw e;//rethrow to avoid it getting caught with the IOException
//        } catch (IOException e) {
//            throw new RuntimeException(e);//todo
//        }
    }

    public static void main(String[] args) throws InvalidKeyException, CorruptedFileException, InvalidPasswordException {
        final String file = "D:/dexcrypttest/files/video.mp4";
        final char[] password = "supersecret".toCharArray();
        final String encryptedFile = file + ".dxp";
        new Encrypter(DEFAULT_BUFFER_SIZE, password, file, encryptedFile, false)
                .encrypt();

        new Encrypter(DEFAULT_BUFFER_SIZE, password, encryptedFile, FileUtils.getDecryptedName(encryptedFile), false)
                .decrypt();
    }

}
