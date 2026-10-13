// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.crypto;

/// Wrapper for cryptography-related exceptions.
///
/// This unchecked exception is thrown by all crypto operations when an error occurs,
/// such as invalid password, corrupted ciphertext, or algorithm failures.
///
/// @since 1.0.0
public class CryptographyException extends RuntimeException {
    /// Creates an instance with the specified cause.
    ///
    /// @param cause the cause
    public CryptographyException(Throwable cause) {
        super(cause);
    }
}
