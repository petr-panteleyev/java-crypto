# Java Crypto

[![License](https://www.panteleyev.org/badges/license-bsd-2.svg)](LICENSE)
[![JDK](https://www.panteleyev.org/badges/java-25.svg)](https://jdk.java.net/archive/)

Basic crypto API with authenticated encryption and secure password generation.

## Features

- **AES-256/GCM** authenticated encryption (confidentiality + integrity)
- **AES-256/CBC** legacy encryption
- **PBKDF2** key derivation (600,000 iterations with salt) for GCM API
- **Secure password generator** with configurable character sets

## Artifact

```xml
<dependency>
    <groupId>org.panteleyev</groupId>
    <artifactId>org-panteleyev-crypto</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

### GCM Encryption (Recommended)

```java
import org.panteleyev.crypto.AESGCM;

AESGCM aes = AESGCM.aes256();

// Encrypt
byte[] encrypted = aes.encrypt("Hello, World!", "my-password");

// Decrypt
String decrypted = aes.decryptString(encrypted, "my-password");
```

### Legacy Encryption

```java
import org.panteleyev.crypto.AES;

AES aes = AES.aes256();

// Encrypt
byte[] encrypted = aes.encrypt("Hello, World!", "my-password");

// Decrypt
String decrypted = aes.decryptString(encrypted, "my-password");
```

### Password Generation

```java
import org.panteleyev.password.PasswordGenerator;
import org.panteleyev.password.PasswordCharacterSet;
import java.util.Set;

PasswordGenerator generator = new PasswordGenerator();
Set<PasswordCharacterSet> sets = Set.of(
    PasswordCharacterSet.UPPER_CASE_LETTERS,
    PasswordCharacterSet.LOWER_CASE_LETTERS,
    PasswordCharacterSet.DIGITS,
    PasswordCharacterSet.SYMBOLS
);
String password = generator.generate(sets, 16);
```

## References

* [API Documentation](https://www.panteleyev.org/javadoc/java-crypto/)
