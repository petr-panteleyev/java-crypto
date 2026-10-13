// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/// Package-private implementation of AES encryption/decryption.
///
/// Uses SHA-256 for key derivation and AES/CBC/PKCS5Padding for encryption.
///
/// Encrypted data format: `[IV 16B][ciphertext]`
class AESImpl implements AES {
    private static final String ALGO = "AES";
    private static final String ALGO_FULL = ALGO + "/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;

    private static final int FILE_BUF_SIZE = 4096;

    private static final AESImpl INSTANCE = new AESImpl();

    private final SecureRandom random = new SecureRandom();

    static byte[] generateKey(String password) throws NoSuchAlgorithmException {
        var md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    static AES getInstance() {
        return INSTANCE;
    }

    private AESImpl() {
    }

    private byte[] generateIV() {
        var res = new byte[IV_LENGTH];
        random.nextBytes(res);
        return res;
    }

    @Override
    public byte[] encrypt(byte[] src, String password) {
        try {
            var iv = generateIV();
            var key = generateKey(password);
            var cipher = Cipher.getInstance(ALGO_FULL);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGO), new IvParameterSpec(iv));
            var encrypted = cipher.doFinal(src);
            var res = Arrays.copyOf(iv, iv.length + encrypted.length);
            for (int i = 0, j = iv.length; i < encrypted.length; i++, j++) {
                res[j] = encrypted[i];
            }
            return res;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public void encrypt(byte[] src, String password, OutputStream out) {
        try (var cOut = getOutputStream(out, password)) {
            cOut.write(src);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] bytes, String password) {
        if (bytes.length <= IV_LENGTH) {
            throw new IllegalArgumentException("Byte array to decrypt is too short");
        }

        try {
            var key = generateKey(password);
            var iv = Arrays.copyOf(bytes, IV_LENGTH);
            var cipher = Cipher.getInstance(ALGO_FULL);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGO), new IvParameterSpec(iv));
            return cipher.doFinal(bytes, IV_LENGTH, bytes.length - IV_LENGTH);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public String decryptString(byte[] bytes, String password) {
        var res = decrypt(bytes, password);
        return new String(res, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(InputStream in, String password) {
        if (in instanceof CipherInputStream) {
            throw new IllegalArgumentException("CipherInputStream must not be passed");
        }

        try (var out = new ByteArrayOutputStream()) {
            try (var cin = getInputStream(in, password)) {
                var buf = new byte[FILE_BUF_SIZE];
                int nRead;
                while ((nRead = cin.read(buf)) > 0) {
                    out.write(buf, 0, nRead);
                }
            }
            return out.toByteArray();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public InputStream getInputStream(InputStream in, String password) {
        try {
            var iv = new byte[IV_LENGTH];
            for (int i = 0; i < IV_LENGTH; i++) {
                int b = in.read();
                if (b == -1) {
                    throw new IOException("premature end of stream");
                }
                iv[i] = (byte) b;
            }

            var key = generateKey(password);
            var cipher = Cipher.getInstance(ALGO_FULL);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGO), new IvParameterSpec(iv));
            return new CipherInputStream(in, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException ex) {
            throw new CryptographyException(ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public OutputStream getOutputStream(OutputStream out, String password) {
        try {
            var iv = generateIV();
            var key = generateKey(password);
            var cipher = Cipher.getInstance(ALGO_FULL);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGO), new IvParameterSpec(iv));
            out.write(iv);
            return new CipherOutputStream(out, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException ex) {
            throw new CryptographyException(ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
