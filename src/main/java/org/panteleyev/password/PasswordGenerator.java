// Copyright © 2017-2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.password;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.Set;

/// Implements password generation functionality.
///
/// The following characters are considered ambiguous from visual standpoint: `I l O`. They are excluded by default and
/// can be included with [#generate(Set, int, boolean)].
///
/// Password length must be at least 4 in order to ensure all specified character sets can be present in the generated
/// string. There is no upper limit for password length.
///
public final class PasswordGenerator {
    private final SecureRandom random = new SecureRandom();

    /// Creates an instance of `PasswordGenerator`.
    public PasswordGenerator() {
    }

    /// Generates password and avoids ambiguous letters.
    ///
    /// @param characterSets password character sets
    /// @param length        password length
    /// @return password
    /// @throws NullPointerException     if characterSets is null
    /// @throws IllegalArgumentException if no character sets are selected or password length < 4
    public String generate(Set<PasswordCharacterSet> characterSets, int length) {
        return generate(characterSets, length, false);
    }

    /// Generates password.
    ///
    /// @param characterSets         password character sets
    /// @param length                password length
    /// @param allowAmbiguousLetters true if set of ambiguous letters should be included
    /// @return password
    /// @throws NullPointerException     if characterSets is null
    /// @throws IllegalArgumentException if no character sets are selected or password length < 4
    public String generate(Set<PasswordCharacterSet> characterSets, int length, boolean allowAmbiguousLetters) {
        Objects.requireNonNull(characterSets, "Character sets cannot be null");
        if (characterSets.isEmpty()) {
            throw new IllegalArgumentException("At least one character set must be used");
        }
        if (length < 4) {
            throw new IllegalArgumentException("Password length must be at least 4");
        }

        var password = new char[length];

        var setArray = new PasswordCharacterSet[characterSets.size()];
        characterSets.toArray(setArray);

        // Pick one character from each set for guaranteed representation
        var index = 0;
        for (var charSet : setArray) {
            password[index++] = charSet.nextCharacter(allowAmbiguousLetters, random);
        }

        // Fill remaining positions randomly
        for (var i = index; i < length; i++) {
            var charSet = setArray[random.nextInt(setArray.length)];
            password[i] = charSet.nextCharacter(allowAmbiguousLetters, random);
        }

        shuffle(password, random);
        return new String(password);
    }

    private static void shuffle(char[] array, SecureRandom random) {
        for (var i = array.length - 1; i > 0; i--) {
            var j = random.nextInt(i + 1);
            var temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }
}
