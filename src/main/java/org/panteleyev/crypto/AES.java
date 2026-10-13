// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/// This interface provides methods for AES encryption and decryption.
public interface AES {
    /// Encrypt string.
    ///
    /// @param str      string
    /// @param password password
    /// @return encrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    default byte[] encrypt(String str, String password) {
        return encrypt(str.getBytes(StandardCharsets.UTF_8), password);
    }

    /// Encrypt byte array.
    ///
    /// @param src      byte array
    /// @param password password
    /// @return encrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    byte[] encrypt(byte[] src, String password);

    /// Encrypt bytes and write the result into the stream.
    ///
    /// @param src      bytes to encrypt
    /// @param password password
    /// @param out      stream
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs
    void encrypt(byte[] src, String password, OutputStream out);

    /// Encrypt string and write the result into the stream.
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
    /// @param bytes    bytes to decrypt
    /// @param password password to decrypt
    /// @return decrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    byte[] decrypt(byte[] bytes, String password);

    /// Decrypt string
    ///
    /// @param bytes    bytes to decrypt
    /// @param password password to decrypt
    /// @return decrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    String decryptString(byte[] bytes, String password);

    /// Decrypt input stream. Stream must be obtained via [#getInputStream(InputStream, String)].
    ///
    /// @param in       stream to decrypt
    /// @param password password to decrypt
    /// @return decrypted bytes
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    byte[] decrypt(InputStream in, String password);

    /// Returns input stream to decrypt encrypted stream with password.
    ///
    /// @param in       encrypted stream
    /// @param password password
    /// @return instance of [CipherInputStream]
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs
    InputStream getInputStream(InputStream in, String password);

    /// Returns output stream to encrypt given output stream.
    ///
    /// @param out      output stream
    /// @param password password
    /// @return instance of [CipherOutputStream]
    /// @throws CryptographyException if cryptography related error occurs
    /// @throws UncheckedIOException  if an I/O error occurs.
    OutputStream getOutputStream(OutputStream out, String password);

    /// Return AES instance with default 256-bit key generation function.
    ///
    /// @return AES instance
    /// @throws CryptographyException if cryptography related error occurs
    static AES aes256() {
        return AESImpl.getInstance();
    }
}
