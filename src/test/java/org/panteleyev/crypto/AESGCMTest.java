// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;

public class AESGCMTest {
    private static final String PASSWORD = randomString();
    private static final String TEXT = "This is 1st line of text\nSecond line\nThird line";

    @Test
    public void testAESGCM256EncryptDecrypt() {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);
        var dec = aes.decrypt(enc, PASSWORD);
        assertEquals(TEXT, new String(dec, StandardCharsets.UTF_8), "Decoded text is the same as original");
        assertEquals(TEXT, aes.decryptString(enc, PASSWORD), "Decoded text is the same as original");
    }

    @Test
    public void testAESGCMInputStreamDecrypt() throws Exception {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);

        try (var in = new ByteArrayInputStream(enc)) {
            var dec = aes.decrypt(in, PASSWORD);
            assertEquals(TEXT, new String(dec, StandardCharsets.UTF_8), "Decoded text is the same as original");
        }
    }

    @Test
    public void testAESGCMOutputStreamEncrypt() throws Exception {
        var aes = AESGCM.aes256();

        try (var out = new ByteArrayOutputStream()) {
            aes.encrypt(TEXT, PASSWORD, out);

            var decrypted = aes.decryptString(out.toByteArray(), PASSWORD);
            assertEquals(TEXT, decrypted);
        }
    }

    @Test
    public void testNewInstance() {
        var aes256_1 = AESGCM.aes256();
        var aes256_2 = AESGCM.aes256();
        assertSame(aes256_1, aes256_2);
    }

    @Test
    public void testAESGCMgetOutputStream() throws Exception {
        var aes256 = AESGCM.aes256();

        try (var out = new ByteArrayOutputStream()) {
            try (var cout = aes256.getOutputStream(out, PASSWORD)) {
                cout.write(TEXT.getBytes(StandardCharsets.UTF_8));
            }

            var encrypted = out.toByteArray();
            var decrypted = aes256.decryptString(encrypted, PASSWORD);
            assertEquals(TEXT, decrypted);
        }
    }

    @Test
    public void testEmptyStringEncryptDecrypt() {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt("", PASSWORD);
        var dec = aes.decryptString(enc, PASSWORD);
        assertEquals("", dec);
    }

    @Test
    public void testWrongPasswordThrowsException() {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);
        assertThrows(CryptographyException.class, () -> aes.decryptString(enc, "wrong-password"));
    }

    @Test
    public void testCorruptedCiphertextThrowsException() {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);
        // Flip a byte in the middle of the ciphertext
        var corrupted = enc.clone();
        corrupted[corrupted.length / 2] ^= 0x01;
        assertThrows(CryptographyException.class, () -> aes.decryptString(corrupted, PASSWORD));
    }

    @Test
    public void testTooShortInputThrowsException() {
        var aes = AESGCM.aes256();
        assertThrows(IllegalArgumentException.class, () -> aes.decrypt(new byte[]{1, 2, 3}, PASSWORD));
    }

    @Test
    public void testLargeDataEncryptDecrypt() throws Exception {
        var aes = AESGCM.aes256();
        var largeText = "A".repeat(100_000);
        var enc = aes.encrypt(largeText, PASSWORD);
        var dec = aes.decryptString(enc, PASSWORD);
        assertEquals(largeText, dec);
    }

    @Test
    public void testDecryptStringWithStream() throws Exception {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);

        try (var in = new ByteArrayInputStream(enc)) {
            var dec = aes.decryptString(in, PASSWORD);
            assertEquals(TEXT, dec);
        }
    }

    @Test
    public void testDecryptedLength() {
        var aes = AESGCM.aes256();
        var enc = aes.encrypt(TEXT, PASSWORD);
        var expectedLength = aes.decryptString(enc, PASSWORD).length();
        assertEquals(expectedLength, AESGCM.decryptedLength(enc));
    }

    private static String randomString() {
        return Long.toHexString(System.nanoTime());
    }
}
