// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause

/// Java Crypto - AES-256 encryption and secure password generation.
///
/// Provides authenticated encryption (AES/GCM) with PBKDF2 key derivation,
/// plus a cryptographically secure password generator with configurable character sets.
///
/// @since 1.0.0
module org.panteleyev.crypto {
    exports org.panteleyev.crypto;
    exports org.panteleyev.password;
}
