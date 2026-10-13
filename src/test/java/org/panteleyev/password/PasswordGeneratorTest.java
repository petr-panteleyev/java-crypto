// Copyright © 2026 Petr Panteleyev
// SPDX-License-Identifier: BSD-2-Clause
package org.panteleyev.password;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Set;

import static java.util.Arrays.binarySearch;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordGeneratorTest {
    private static List<Arguments> testPasswordContentData() {
        return List.of(
                Arguments.of(Set.of(PasswordCharacterSet.UPPER_CASE_LETTERS)),
                Arguments.of(Set.of(PasswordCharacterSet.LOWER_CASE_LETTERS)),
                Arguments.of(Set.of(PasswordCharacterSet.DIGITS)),
                Arguments.of(Set.of(PasswordCharacterSet.SYMBOLS)),
                Arguments.of(Set.of(PasswordCharacterSet.values()))
        );
    }

    @Test
    public void testPasswordLength() {
        for (var length = 4; length <= 32; length++) {
            assertEquals(length,
                    new PasswordGenerator().generate(Set.of(
                            PasswordCharacterSet.UPPER_CASE_LETTERS), length).length());
        }
    }

    @ParameterizedTest
    @MethodSource("testPasswordContentData")
    public void testPasswordContent(Set<PasswordCharacterSet> options) {
        var passwordCharacters = new PasswordGenerator().generate(options, 48).toCharArray();

        for (var opt : options) {
            assertTrue(hasCharacters(opt.getCharacters(), passwordCharacters));
        }
    }

    @Test
    public void testNoCharacterSetSelected() {
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordGenerator().generate(Set.of(), 8));
    }

    @Test
    public void testWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordGenerator().generate(Set.of(PasswordCharacterSet.DIGITS), 3));
    }

    @Test
    public void testNoAmbiguousLettersExcluded() {
        var generator = new PasswordGenerator();
        var password = generator.generate(Set.of(
                PasswordCharacterSet.UPPER_CASE_LETTERS,
                PasswordCharacterSet.LOWER_CASE_LETTERS), 100);

        assertFalse(password.contains("I"));
        assertFalse(password.contains("O"));
        assertFalse(password.contains("l"));
    }

    @Test
    public void testAmbiguousLettersIncluded() {
        var generator = new PasswordGenerator();
        var password = generator.generate(Set.of(
                PasswordCharacterSet.UPPER_CASE_LETTERS,
                PasswordCharacterSet.LOWER_CASE_LETTERS), 100, true);

        // With 100 chars and 29 upper + 26 lower = 55 possible chars, ambiguous chars should appear
        var hasAmbiguous = password.contains("I") || password.contains("O") || password.contains("l");
        assertTrue(hasAmbiguous, "Ambiguous letters should be allowed when flag is true");
    }

    @Test
    public void testStatisticalDistribution() {
        var generator = new PasswordGenerator();
        var charSet = Set.of(PasswordCharacterSet.DIGITS);
        var digitCounts = new int[10];

        for (int i = 0; i < 10_000; i++) {
            var password = generator.generate(charSet, 10);
            for (var c : password.toCharArray()) {
                digitCounts[c - '0']++;
            }
        }

        // Each digit should appear roughly 10% of the time (±5% tolerance)
        var total = 10_000 * 10;
        for (var count : digitCounts) {
            var percentage = count / (double) total;
            assertTrue(percentage > 0.05 && percentage < 0.15,
                    "Digit distribution should be roughly uniform, got " + percentage);
        }
    }

    @Test
    public void testLargePassword() {
        var generator = new PasswordGenerator();
        var password = generator.generate(Set.of(
                PasswordCharacterSet.UPPER_CASE_LETTERS,
                PasswordCharacterSet.LOWER_CASE_LETTERS,
                PasswordCharacterSet.DIGITS), 1000);
        assertEquals(1000, password.length());
    }

    private static boolean hasCharacters(char[] characters, char[] password) {
        for (var c : password) {
            if (binarySearch(characters, c) >= 0) {
                return true;
            }
        }
        return false;
    }
}