// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/// AES-256 encryption with GCM authenticated encryption and PBKDF2 key derivation.
/// <p>
/// This interface provides authenticated encryption (confidentiality + integrity)
/// using AES/GCM/NoPadding with PBKDF2 key derivation (600,000 iterations).
/// </p>
/// <p>
/// Encrypted data format: `{salt 16B}{nonce 12B}{GCM tag 16B}{ciphertext}`
/// </p>
///
/// @since 1.0.0
public interface AESGCM {
    /// Encrypt string and return encrypted bytes.
    ///
    /// Output format: `{salt 16B}{nonce 12B}{GCM tag 16B}{ciphertext}`
    ///
    /// @param str      string
    /// @param password password
    /// @return encrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    default byte[] encrypt(String str, String password) {
        return encrypt(str.getBytes(StandardCharsets.UTF_8), password);
    }

    /// Encrypt byte array and return encrypted bytes.
    ///
    /// Output format: `{salt 16B}{nonce 12B}{GCM tag 16B}{ciphertext}`
    ///
    /// @param src      byte array
    /// @param password password
    /// @return encrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    byte[] encrypt(byte[] src, String password);

    /// Encrypt bytes and write the result into the stream.
    ///
    /// The output stream is NOT closed by this method.
    ///
    /// @param src      bytes to encrypt
    /// @param password password
    /// @param out      stream
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs
    void encrypt(byte[] src, String password, OutputStream out);

    /// Encrypt string and write the result into the stream.
    ///
    /// The output stream is NOT closed by this method.
    ///
    /// @param str      string to encrypt
    /// @param password password
    /// @param out      stream
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    default void encrypt(String str, String password, OutputStream out) {
        encrypt(str.getBytes(StandardCharsets.UTF_8), password, out);
    }

    /// Decrypt byte array.
    ///
    /// Expects data in format: `{salt 16B}{nonce 12B}{GCM tag 16B}{ciphertext}`
    ///
    /// @param bytes    bytes to decrypt
    /// @param password password to decrypt
    /// @return decrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    byte[] decrypt(byte[] bytes, String password);

    /// Returns the expected length of decrypted data given the encrypted byte array.
    ///
    /// Result: `bytes.length - 44` (16 salt + 12 nonce + 16 tag overhead)
    ///
    /// @param bytes encrypted bytes
    /// @return expected plaintext length, or -1 if format is unrecognized
    static int decryptedLength(byte[] bytes) {
        var overhead = AESGCMImpl.SALT_LENGTH + AESGCMImpl.GCM_NONCE_LENGTH + (AESGCMImpl.GCM_TAG_LENGTH_BITS / 8);
        if (bytes.length >= overhead) {
            return bytes.length - overhead;
        }
        return -1;
    }

    /// Decrypt byte array and return as String.
    ///
    /// @param bytes    bytes to decrypt
    /// @param password password to decrypt
    /// @return decrypted string
    /// @throws CryptographyException if cryptography related error occurs
    String decryptString(byte[] bytes, String password);

    /// Decrypt input stream. A `CipherInputStream` must not be passed.
    ///
    /// Note: the entire stream is read into memory to validate the encrypted data
    /// format (GCM tag). For large data, prefer `decrypt(byte[], String)` with byte arrays.
    ///
    /// @param in       stream to decrypt
    /// @param password password to decrypt
    /// @return decrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    byte[] decrypt(InputStream in, String password);

    /// Decrypt input stream and return as String.
    ///
    /// @param in       stream to decrypt
    /// @param password password to decrypt
    /// @return decrypted string
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    default String decryptString(InputStream in, String password) {
        return new String(decrypt(in, password), StandardCharsets.UTF_8);
    }

    /// Returns input stream to decrypt encrypted stream with password.
    ///
    /// @param in       encrypted stream
    /// @param password password
    /// @return instance of `CipherInputStream`
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs
    InputStream getInputStream(InputStream in, String password);

    /// Returns output stream to encrypt given output stream.
    ///
    /// @param out      output stream
    /// @param password password
    /// @return instance of `CipherOutputStream`
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    OutputStream getOutputStream(OutputStream out, String password);

    /// Return AESGCM instance with default 256-bit key generation function.
    /// Uses PBKDF2 with SHA-256 (600,000 iterations) and AES/GCM/NoPadding.
    ///
    /// @return AESGCM instance
    /// @throws CryptographyException if cryptography related error occurs
    static AESGCM aes256() {
        return AESGCMImpl.getInstance();
    }
}
