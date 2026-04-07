# Contributing to risaal_crypto

Thank you for your interest in contributing to `risaal_crypto`.

**This is a security-critical cryptographic library.** All contributions are welcome, but please understand that code changes affecting cryptographic primitives will receive extra scrutiny.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR-USERNAME/risaal-crypto.git
cd risaal-crypto/packages/risaal_crypto
```

### 2. Install Dependencies

```bash
flutter pub get
```

### 3. Verify Your Environment

Run the test suite to ensure everything works:

```bash
flutter test
```

All tests must pass. The current test suite includes 200+ tests across 13 test files.

Run static analysis:

```bash
flutter analyze
```

Must pass with zero warnings or errors.

## Development Guidelines

### Code Style

- Follow [Effective Dart](https://dart.dev/guides/language/effective-dart) style guide
- Run `dart format .` before committing
- Use `flutter analyze` to catch style violations

### Documentation

- **All public APIs must have dartdoc comments**
- Include example usage in doc comments for complex APIs
- Document parameters, return values, and thrown exceptions
- Add `@nodoc` for internal APIs not meant for public use

Example:

```dart
/// Generates a new X3DH identity key bundle.
///
/// Returns a [SignalIdentityKeyPair] containing both the private
/// and public identity keys. The private key is stored securely
/// via [CryptoSecureStorage] and never exposed in plaintext.
///
/// Throws [CryptoException] if key generation fails.
Future<SignalIdentityKeyPair> generateIdentityKeyPair() async {
  // implementation
}
```

### Logging

- **NEVER use `print()` statements**
- Use `CryptoDebugLogger` for debug logging (automatically stripped from release builds)
- **NEVER log private keys, plaintext, or full key material**
- Only log key prefixes (first 8 characters) for debugging

Example:

```dart
// Good
CryptoDebugLogger.log('Generated prekey: ${preKeyPublic.substring(0, 8)}...');

// Bad - NEVER DO THIS
print('Private key: $privateKey'); // Leaks secrets in logs!
```

### Memory Safety

- **All sensitive key material must be zeroed after use**
- Use `SecureMemory.zeroBytes(data)` for Uint8List
- Prefer `const` constructors where possible
- Avoid storing sensitive data in class fields longer than necessary

Example:

```dart
Future<void> processMessage(Uint8List encryptedData) async {
  final sharedSecret = await computeSharedSecret();
  try {
    // Use the shared secret
    final plaintext = await decrypt(encryptedData, sharedSecret);
    return plaintext;
  } finally {
    // Always zero sensitive data
    SecureMemory.zeroBytes(sharedSecret);
  }
}
```

## Testing Requirements

**ALL CRYPTOGRAPHIC CHANGES MUST INCLUDE TESTS.**

This is non-negotiable. Untested cryptographic code will not be merged.

### Minimum Coverage

- **80% test coverage** for all cryptographic code
- 100% coverage preferred for security-critical functions (key generation, encryption, decryption)

### Test Categories

For any cryptographic change, include tests in these categories:

#### 1. Positive Tests

Verify correct behavior under normal conditions.

```dart
test('encrypt and decrypt message successfully', () async {
  final plaintext = utf8.encode('Hello, world!');
  final ciphertext = await encrypt(plaintext, key);
  final decrypted = await decrypt(ciphertext, key);
  expect(decrypted, equals(plaintext));
});
```

#### 2. Negative Tests

Verify rejection of invalid inputs.

```dart
test('decrypt fails with wrong key', () async {
  final ciphertext = await encrypt(plaintext, correctKey);
  expect(
    () => decrypt(ciphertext, wrongKey),
    throwsA(isA<CryptoException>()),
  );
});

test('decrypt fails with corrupted ciphertext', () async {
  final ciphertext = await encrypt(plaintext, key);
  ciphertext[0] ^= 0xFF; // Flip bits
  expect(
    () => decrypt(ciphertext, key),
    throwsA(isA<CryptoException>()),
  );
});
```

#### 3. Adversarial Tests

Verify resistance to attacks.

```dart
test('prevents replay attack via message number', () async {
  final msg1 = await encryptMessage(session, 'First message');
  await decryptMessage(session, msg1); // OK

  // Replaying the same message should fail
  expect(
    () => decryptMessage(session, msg1),
    throwsA(isA<DuplicateMessageException>()),
  );
});

test('prevents message reordering', () async {
  final msg1 = await encryptMessage(session, 'Message 1');
  final msg2 = await encryptMessage(session, 'Message 2');

  await decryptMessage(session, msg2); // Deliver out of order

  // msg1 should now be rejected as too old
  expect(
    () => decryptMessage(session, msg1),
    throwsA(isA<MessageTooOldException>()),
  );
});
```

#### 4. Boundary Tests

Verify edge cases.

```dart
test('handles empty message', () async {
  final empty = Uint8List(0);
  final ciphertext = await encrypt(empty, key);
  final decrypted = await decrypt(ciphertext, key);
  expect(decrypted, isEmpty);
});

test('handles maximum message size', () async {
  final maxSize = Uint8List(1024 * 1024); // 1MB
  final ciphertext = await encrypt(maxSize, key);
  final decrypted = await decrypt(ciphertext, key);
  expect(decrypted.length, equals(maxSize.length));
});
```

### Test Helpers

Use the provided test helpers:

- **`FakeSecureStorage`**: Mock implementation of `CryptoSecureStorage` for tests
- **`CryptoTestFixtures`**: Pregenerated test keys and data

Example:

```dart
import 'package:risaal_crypto/src/crypto_secure_storage.dart';
import 'helpers/crypto_test_fixtures.dart';

void main() {
  late FakeSecureStorage storage;

  setUp(() {
    storage = FakeSecureStorage();
  });

  test('stores identity key pair', () async {
    final keyPair = CryptoTestFixtures.identityKeyPair;
    await storage.storeIdentityKeyPair(keyPair);

    final retrieved = await storage.getIdentityKeyPair();
    expect(retrieved.publicKey, equals(keyPair.publicKey));
  });
}
```

### Running Tests

```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/double_ratchet_test.dart

# Run with coverage (requires coverage package)
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
```

## Pull Request Process

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Test additions or improvements

### 2. Write Tests First (TDD Recommended)

Write tests for the functionality you're adding BEFORE implementing it. This ensures:
- Your API design makes sense
- You think through edge cases upfront
- You have regression protection

### 3. Implement the Feature

Write the code to make your tests pass.

### 4. Run Quality Checks

```bash
# Format code
dart format .

# Run static analysis
flutter analyze

# Run all tests
flutter test
```

All checks must pass with zero issues.

### 5. Update CHANGELOG.md

Add an entry under `## [Unreleased]` describing your change:

```markdown
## [Unreleased]

### Added
- New `SessionResetManager` for automatic session recovery

### Fixed
- Fixed race condition in `DoubleRatchet` when processing out-of-order messages

### Security
- [SECURITY] Added constant-time comparison for authentication tags
```

Use the `[SECURITY]` prefix for security-relevant changes.

### 6. Submit Pull Request

- Clear title summarizing the change
- Description explaining:
  - What problem does this solve?
  - How does it solve it?
  - Any breaking changes?
  - Testing performed
- Reference any related issues with `Fixes #123`

### 7. Code Review

Your PR will be reviewed by maintainers. We may request changes or ask questions. Please be patient and responsive.

## Security-Sensitive Changes

Changes to these files require **extra scrutiny** and will have stricter review requirements:

### Core Cryptographic Files

- `lib/src/x3dh.dart` - X3DH key agreement protocol
- `lib/src/double_ratchet.dart` - Double Ratchet message encryption
- `lib/src/sealed_sender.dart` - Sealed Sender metadata protection
- `lib/src/sender_key.dart` - Sender Key group encryption
- `lib/src/key_helper.dart` - Cryptographic key generation
- `lib/src/secure_memory.dart` - Secure memory management

### Requirements for Security-Sensitive Changes

1. **At least 2 reviewers required** (maintainers will assign reviewers)
2. **Adversarial test cases mandatory** (replay, tampering, timing)
3. **Cryptographic rationale required** in PR description:
   - Why is this change necessary?
   - What cryptographic property does it maintain or improve?
   - What are the security implications?
   - Have you verified this doesn't introduce timing side channels?
4. **References to specifications** (Signal Protocol specs, RFCs, academic papers)

Example PR description for security-sensitive change:

```markdown
## Add Constant-Time MAC Verification

### Problem
Current MAC verification uses `==` which may leak timing information
about the position of the first differing byte.

### Solution
Implement constant-time comparison via bitwise XOR accumulation.

### Security Rationale
Prevents timing side-channel attacks where an attacker iteratively
guesses MAC bytes by measuring response times.

### References
- RFC 2104 (HMAC) Section 6 - Security Considerations
- "A Lesson In Timing Attacks" by Nate Lawson
- Signal Protocol Spec Section 5.2

### Testing
Added adversarial test case measuring timing distribution across
10,000 iterations with varying MAC mismatches.
```

## Types of Contributions We Need

### High Priority

- **More test coverage** - Especially adversarial and boundary tests
- **Formal verification** - Proofs of correctness for cryptographic primitives
- **Performance benchmarks** - Profiling and optimization of hot paths
- **Security audit** - Independent review by cryptography experts

### Medium Priority

- **Documentation improvements** - Better examples, tutorials, diagrams
- **Platform-specific optimizations** - Leverage native crypto where available
- **Error handling improvements** - Better error messages and recovery

### Lower Priority

- **Code cleanup** - Refactoring, DRY violations
- **Build improvements** - CI/CD, linting rules
- **Example apps** - Demonstrating library usage

## Code of Conduct

### Our Standards

- **Be respectful:** Treat all contributors with respect, regardless of experience level
- **Be constructive:** Focus feedback on the code, not the person
- **Be security-minded:** Assume good faith, but verify cryptographic claims
- **Be patient:** Security reviews take time; quality over speed

### Unacceptable Behavior

- Personal attacks, harassment, or discrimination
- Publishing private information without permission
- Deliberately introducing security vulnerabilities
- Ignoring security review feedback

### Enforcement

Violations will result in warnings, temporary bans, or permanent bans depending on severity. Contact hello@risaal.org to report Code of Conduct violations.

## Questions?

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Open a GitHub Issue (not for security bugs!)
- **Security vulnerabilities:** Email security@risaal.org (see SECURITY.md)
- **Feature requests:** Open a GitHub Issue with the `enhancement` label

## Recognition

All contributors will be acknowledged in the CHANGELOG and/or CONTRIBUTORS file. Security researchers who responsibly disclose vulnerabilities will be thanked in release notes (unless they prefer anonymity).

Thank you for contributing to secure communications.
