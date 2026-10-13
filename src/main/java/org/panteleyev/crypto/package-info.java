// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause

/// AES-256 encryption with GCM authenticated encryption and PBKDF2 key derivation.
///
/// Provides both byte-array and stream-based APIs for encryption/decryption.
/// Supports backward compatibility with legacy SHA-256/AES-CBC format.
///
/// @since 1.0.0
package org.panteleyev.crypto;
