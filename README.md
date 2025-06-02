Production-grade cryptographic library for the AeroNyx Decentralized Private Infrastructure Network (DePIN). Provides secure, cross-platform cryptographic primitives optimized for decentralized VPN and privacy-preserving compute networks.
🚀 Features
Core Cryptography

Modern Algorithms: ChaCha20-Poly1305, AES-256-GCM, Ed25519, X25519
Hardware Acceleration: AES-NI, AVX2, ARM NEON support
Memory Safety: Automatic zeroing of sensitive data with secure memory handling
Standards Compliant: FIPS 140-3, NIST SP 800-57, Solana-compatible

Platform Integration

Secure Storage:

Windows: Credential Manager with DPAPI
macOS/iOS: Keychain with Secure Enclave
Android: Hardware-backed Keystore
Linux: Secret Service API


Mobile Optimized: Power-aware encryption, network-adaptive algorithms
Cross-Platform: Universal binary support for all major platforms

Developer Experience

Multiple Language Bindings: Rust, C, Swift, Kotlin, C#
Comprehensive Examples: Real-world usage patterns
Type Safety: Strong typing with compile-time guarantees
Extensive Documentation: API docs and integration guides

📦 Installation
Rust Project
Add to your Cargo.toml:
toml[dependencies]
aeronyx-crypto = "0.2.0"
iOS/macOS (Swift)
Using Swift Package Manager:
swiftdependencies: [
    .package(url: "https://github.com/AeroNyxNetwork/aeronyx_crypto", from: "0.2.0")
]
Or using CocoaPods:
rubypod 'AeroNyxCrypto', '~> 0.2.0'
Android (Kotlin/Java)
Add to your build.gradle:
gradledependencies {
    implementation 'com.aeronyx:crypto:0.2.0'
}
Building from Source
bash# Clone the repository
git clone https://github.com/AeroNyxNetwork/aeronyx_crypto
cd aeronyx-crypto

# Build for your platform
cargo build --release

# Build with all features
cargo build --release --all-features

# Build for iOS (requires Xcode)
./build-ios.sh

# Run tests
cargo test
🔧 Usage Examples
Basic Encryption
rustuse aeronyx_crypto::{generate_keypair, encrypt_chacha20, decrypt_chacha20};

// Generate a keypair
let (private_key, public_key) = generate_keypair()?;

// Encrypt data
let plaintext = b"Hello, AeroNyx!";
let key = [0u8; 32]; // Use a proper key derivation function
let (ciphertext, nonce) = encrypt_chacha20(plaintext, &key)?;

// Decrypt data
let decrypted = decrypt_chacha20(&ciphertext, &key, &nonce)?;
assert_eq!(decrypted, plaintext);
Digital Signatures
rustuse aeronyx_crypto::{sign_message, verify_signature};

// Sign a message
let message = b"Authenticate me";
let signature = sign_message(&private_key, message)?;

// Verify signature
let is_valid = verify_signature(&public_key, message, &signature)?;
assert!(is_valid);
Key Exchange (ECDH)
rustuse aeronyx_crypto::{generate_keypair, derive_shared_secret};

// Alice and Bob generate their keypairs
let (alice_private, alice_public) = generate_keypair()?;
let (bob_private, bob_public) = generate_keypair()?;

// Derive shared secret
let alice_shared = derive_shared_secret(&alice_private, &bob_public)?;
let bob_shared = derive_shared_secret(&bob_private, &alice_public)?;

assert_eq!(alice_shared, bob_shared);
Secure Storage (Platform-Specific)
rustuse aeronyx_crypto::platform::get_secure_storage;

let storage = get_secure_storage();
let key_id = "my_secret_key";
let secret_data = b"sensitive information";

// Store securely
storage.store_key(key_id, secret_data)?;

// Retrieve
let retrieved = storage.get_key(key_id)?;

// Delete
storage.delete_key(key_id)?;
🏗️ Architecture
Library Structure
aeronyx-crypto/
├── src/
│   ├── crypto.rs           # Core cryptographic operations
│   ├── auth/               # Authentication subsystem
│   │   ├── challenge.rs    # Challenge-response authentication
│   │   ├── acl.rs         # Access control lists
│   │   └── manager.rs     # Authentication manager
│   ├── platform/          # Platform-specific implementations
│   │   ├── windows.rs     # Windows Credential Manager
│   │   ├── macos.rs       # macOS Keychain
│   │   ├── ios.rs         # iOS Keychain + Secure Enclave
│   │   ├── android.rs     # Android Keystore
│   │   └── linux.rs       # Linux Secret Service
│   ├── protocol/          # AeroNyx protocol support
│   ├── standards/         # Compliance implementations
│   └── ffi/              # Foreign Function Interface
├── examples/             # Usage examples
├── benches/             # Performance benchmarks
└── tests/              # Integration tests
Integration with AeroNyx Network
The library is designed to integrate seamlessly with AeroNyx nodes:

Account Generation: Ed25519 keypairs compatible with Solana
Authentication: Challenge-response authentication with nodes
Encryption: Flexible algorithm selection (ChaCha20/AES-GCM)
Session Management: Secure session key derivation and rotation

🔒 Security
Security Features

Memory Protection: Automatic zeroing of sensitive data
Side-Channel Resistance: Constant-time operations where applicable
Key Protection: Hardware-backed storage when available
Audit Trail: Comprehensive logging for security events

Compliance

FIPS 140-3: Validated cryptographic modules
NIST SP 800-57: Key management recommendations
Common Criteria: EAL4+ design principles

Vulnerability Reporting
Please report security vulnerabilities to: security@aeronyx.network
See SECURITY.md for our security policy.
📊 Performance
Benchmarks on Apple M1 Pro:
OperationPerformanceNotesChaCha20-Poly13053.2 GB/sHardware acceleratedAES-256-GCM5.1 GB/sAES-NI enabledEd25519 Sign52,000 ops/sConstant timeEd25519 Verify19,000 ops/sBatch capableX25519 ECDH31,000 ops/sSide-channel resistant
Run benchmarks:
bashcargo bench
🛠️ Development
Prerequisites

Rust 1.70+ (for GATs and latest features)
Platform SDKs:

Windows: Windows SDK 10.0+
macOS: Xcode 13+
iOS: iOS SDK 13.0+
Android: NDK r21+



Building Documentation
bashcargo doc --all-features --open
Running Tests
bash# All tests
cargo test --all-features

# Platform-specific tests
cargo test --features "std,platform-windows" --target x86_64-pc-windows-msvc
cargo test --features "std,platform-ios" --target aarch64-apple-ios
Contributing
See CONTRIBUTING.md for contribution guidelines.
📄 License
This project is dual-licensed under:

MIT License (LICENSE-MIT or http://opensource.org/licenses/MIT)
Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)


🙏 Acknowledgments
This library builds upon excellent work from:

RustCrypto - Cryptographic algorithms
ring - Crypto primitives
sodiumoxide - libsodium bindings

Special thanks to the Solana and Rust communities for their invaluable contributions to the ecosystem.

Built with ❤️ by the AeroNyx Team
