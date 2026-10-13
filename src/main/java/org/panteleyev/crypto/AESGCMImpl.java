// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/// Package-private implementation of AESGCM encryption/decryption.
///
/// Uses PBKDF2 with SHA-256 (600,000 iterations) for key derivation
/// and AES/GCM/NoPadding for authenticated encryption.
///
/// Encrypted data format: `[salt 16B][nonce 12B][GCM tag 16B][ciphertext]`
class AESGCMImpl implements AESGCM {
    static final int GCM_NONCE_LENGTH = 12;
    static final int GCM_TAG_LENGTH_BITS = 128;
    static final int SALT_LENGTH = 16;
    static final int OVERHEAD = SALT_LENGTH + GCM_NONCE_LENGTH + (GCM_TAG_LENGTH_BITS / 8);

    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int FILE_BUF_SIZE = 4096;

    private static final AESGCMImpl INSTANCE = new AESGCMImpl();

    private final SecureRandom random = new SecureRandom();

    private static byte[] generateKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        var spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        var factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    private byte[] generateSalt() {
        var res = new byte[SALT_LENGTH];
        random.nextBytes(res);
        return res;
    }

    static AESGCM getInstance() {
        return INSTANCE;
    }

    private AESGCMImpl() {
    }

    @Override
    public byte[] encrypt(byte[] src, String password) {
        try {
            var salt = this.generateSalt();
            var nonce = this.generateNonce();
            var key = generateKey(password, salt);
            var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            var encrypted = cipher.doFinal(src);
            // encrypted = [ciphertext][tag]
            var res = new byte[salt.length + nonce.length + encrypted.length];
            System.arraycopy(salt, 0, res, 0, salt.length);
            System.arraycopy(nonce, 0, res, salt.length, nonce.length);
            System.arraycopy(encrypted, 0, res, salt.length + nonce.length, encrypted.length);
            return res;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException |
                 InvalidKeySpecException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public void encrypt(byte[] src, String password, OutputStream out) {
        try {
            var salt = this.generateSalt();
            var nonce = this.generateNonce();
            var key = generateKey(password, salt);
            var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

            out.write(salt);
            out.write(nonce);

            var encrypted = cipher.doFinal(src);
            out.write(encrypted);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException |
                 InvalidKeySpecException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] bytes, String password) {
        if (bytes.length < OVERHEAD) {
            throw new IllegalArgumentException("Byte array is too short");
        }
        try {
            var salt = Arrays.copyOf(bytes, SALT_LENGTH);
            var nonce = Arrays.copyOfRange(bytes, SALT_LENGTH, SALT_LENGTH + GCM_NONCE_LENGTH);
            var cipherTextAndTag = Arrays.copyOfRange(bytes, SALT_LENGTH + GCM_NONCE_LENGTH, bytes.length);
            var key = generateKey(password, salt);
            var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            return cipher.doFinal(cipherTextAndTag);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeySpecException ex) {
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

        try (var baos = new ByteArrayOutputStream()) {
            var buf = new byte[FILE_BUF_SIZE];
            int n;
            while ((n = in.read(buf)) > 0) {
                baos.write(buf, 0, n);
            }
            var allBuf = baos.toByteArray();

            // Validate format by decrypting full data
            try {
                var salt = Arrays.copyOf(allBuf, SALT_LENGTH);
                var nonce = Arrays.copyOfRange(allBuf, SALT_LENGTH, SALT_LENGTH + GCM_NONCE_LENGTH);
                var cipherTextAndTag = Arrays.copyOfRange(allBuf, SALT_LENGTH + GCM_NONCE_LENGTH, allBuf.length);
                var key = generateKey(password, salt);
                var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
                var cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
                cipher.doFinal(cipherTextAndTag);
                // Success
                return decrypt(allBuf, password);
            } catch (Exception ex) {
                throw new CryptographyException(ex);
            }
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public InputStream getInputStream(InputStream in, String password) {
        try {
            // Read salt + nonce header
            var header = new byte[SALT_LENGTH + GCM_NONCE_LENGTH];
            for (int i = 0; i < header.length; i++) {
                int b = in.read();
                if (b == -1) {
                    throw new IOException("premature end of stream");
                }
                header[i] = (byte) b;
            }

            var salt = Arrays.copyOf(header, SALT_LENGTH);
            var nonce = Arrays.copyOfRange(header, SALT_LENGTH, SALT_LENGTH + GCM_NONCE_LENGTH);
            var key = generateKey(password, salt);
            var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

            var pushback = new PushbackInputStream(in, header.length);
            pushback.unread(header, 0, header.length);
            return new CipherInputStream(pushback, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | InvalidKeySpecException ex) {
            throw new CryptographyException(ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Override
    public OutputStream getOutputStream(OutputStream out, String password) {
        try {
            var salt = this.generateSalt();
            var nonce = this.generateNonce();
            var key = generateKey(password, salt);
            var spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            out.write(salt);
            out.write(nonce);
            return new CipherOutputStream(out, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | InvalidKeySpecException ex) {
            throw new CryptographyException(ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private byte[] generateNonce() {
        var res = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(res);
        return res;
    }
}
