// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.password;

import java.security.SecureRandom;

import static java.util.Arrays.binarySearch;
import static java.util.Arrays.sort;

/// Defines password character sets.
public enum PasswordCharacterSet {
    /// Upper case Latin letters.
    UPPER_CASE_LETTERS(new char[]{
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
    }, new char[]{'I', 'O'}),

    /// Lower case Latin letters.
    LOWER_CASE_LETTERS(new char[]{
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    }, new char[]{'l'}),

    /// Digits.
    DIGITS(new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}),

    /// Symbols.
    SYMBOLS(new char[]{'@', '#', '$', '%', '&', '*', '(', ')', '-', '+', '=', '^', '.', ',',
            '!', '~', '`', '{', '}', '[', ']', '\\', '|', ':', ';', '"', '\'', '<', '>', '/', '?'});

    private final char[] characters;
    private final char[] ambiguousCharacters;

    PasswordCharacterSet(char[] characters, char[] ambiguousCharacters) {
        this.characters = characters;
        sort(this.characters);
        this.ambiguousCharacters = ambiguousCharacters;
        sort(this.ambiguousCharacters);
    }

    PasswordCharacterSet(char[] characters) {
        this(characters, new char[0]);
    }

    char nextCharacter(boolean allowAmbiguousLetters, SecureRandom random) {
        while (true) {
            var sym = characters[random.nextInt(characters.length)];
            if (allowAmbiguousLetters || !isAmbiguous(sym)) {
                return sym;
            }
        }
    }

    char[] getCharacters() {
        return characters;
    }

    int length() {
        return characters.length;
    }

    private boolean isAmbiguous(char c) {
        return ambiguousCharacters.length > 0 && binarySearch(ambiguousCharacters, c) >= 0;
    }
}
