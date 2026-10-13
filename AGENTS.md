# AGENTS.md

Instructions for AI coding agents working on this project.

## Project Overview

**Java Crypto** — a zero-dependency Java library providing:
- AES-256/GCM authenticated encryption with PBKDF2 key derivation
- Cryptographically secure password generation

**Group:** `org.panteleyev`  
**Artifact:** `org-panteleyev-crypto`  
**Version:** `1.0.0`  
**Module:** `org.panteleyev.crypto`  
**JDK:** 25  

## Build & Test

```bash
mvn clean test          # Run all tests
mvn clean package       # Build JAR
mvn javadoc:javadoc     # Generate documentation
mvn verify -Prelease    # Build with GPG signing
```

## Code Style

- **Indentation:** 4 spaces (no tabs)
- **Line length:** No hard limit, but prefer readability
- **Naming:** Standard Java conventions (PascalCase classes, camelCase methods/fields)
- **Final fields:** Use `var` for local variables, explicit types for fields
- **Comments:** Use JEP 467 inline `///` comments for public API, `//` for implementation details
- **Javadoc:** Markdown format only — no HTML tags (`<p>`, `<ul>`, `<li>`, `<b>`, `{@code}`)
  - Use backticks for code: `` `CipherInputStream` ``
  - Use backticks to escape javadoc brackets: `` `{salt 16B}` ``
  - Use `- **bold**` for lists, not `<ul>/<li>/<b>`

## Dependencies

This project has **zero runtime dependencies**. Only test dependency is JUnit 5.

## Architecture

Two independent encryption APIs — no fallbacks or auto-detection between them:

- `AES` — legacy API: SHA-256 key derivation, AES/CBC/PKCS5Padding, format `[IV 16B][ciphertext]`
- `AESGCM` — modern API: PBKDF2 (600k iterations, salted), AES/GCM/NoPadding, format `[salt 16B][nonce 12B][GCM tag 16B][ciphertext]`
- `org.panteleyev.password` — Password generation utilities
- `AESImpl` / `AESGCMImpl` — package-private implementations; singletons via `getInstance()`

## Testing

- JUnit 5 with parameterized tests
- Tests live alongside sources in `src/test/java`
- Run `mvn test` before committing — all tests must pass

## Security

- Never introduce weak crypto (no ECB mode, no MD5/SHA-1 for key derivation)
- Always use `SecureRandom` for cryptographic randomness
- Never log secrets, keys, or passwords
- When adding new crypto features, consider: authenticated encryption, key stretching, forward secrecy

## Git

- Squash before push; no merge commits
- Commit title must be "Java Crypto <version>"
- Take version from pom.xml
- Commit messages: concise, imperative mood, focus on "why" not "what"
- Include motivation for changes in commit body
- Add `Co-Authored-By: GigaCode <gigacode@sber.ru>` when AI-assisted
- Reference issues when applicable
