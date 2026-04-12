# 🔐 VaultX: CLI Password Manager

> A secure, local-first password manager written in modern C++. Built to demonstrate applied cryptography, systems integration, and clean architecture.

![C++17](https://img.shields.io/badge/C++-17-blue.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-Cryptography-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**VaultX** (formerly PasswordManager) is a command-line tool that securely stores your credentials. It was engineered from the ground up to focus on strict local-only storage, robust encryption standards, and defense-in-depth system security.

It does not rely on the cloud. Your keys, your data.

---

## ✨ Features

- **Full-File Encryption**: The entire vault is encrypted using AES-256-CBC. IDs are never stored in plaintext.
- **Hardware-Backed Master Keys**: Integrates with TPM 2.0 (`tpm2-tools`) and Linux Secret Service (`libsecret`) for secure key sealing.
- **Cryptographic Rigor**: Passwords derived via PBKDF2-HMAC-SHA256 (200,000 iterations) with per-vault deterministic salting.
- **Modern C++**: Built using C++17 paradigms (`<filesystem>`, RAII wrappers, smart pointers).
- **Stealth Terminal UI**: Real-time masked password inputs and strict terminal mode handling via POSIX `termios`.

---

## 🔒 Security Architecture

This project is built around zero-trust offline principles:

1. **Defense-in-Depth Storage**: Data is encrypted using AES-256-CBC. Every save operation generates a cryptographically secure random IV (16 bytes) via `RAND_bytes`.
2. **Key Derivation**: Vault keys are generated using PBKDF2 (200k iterations). A unique 16-byte random salt is generated on a vault's first creation to prevent rainbow table attacks.
3. **Master Key Sealing**: The system attempts to seal the master metadata key to the machine's TPM (Platform Configuration Registers) tying the vault securely to the physical hardware.
4. **Magic Authentication**: A `"PMGR"` magic bytes header is encrypted within the payload to rapidly validate passwords on load without risking cryptographic leakage.

> **Note on Production Readiness**: While robust, this is a portfolio project. To transition to enterprise production, system shell calls (`popen()`) would be replaced by direct TSS library bindings (`libtss2-esys`), and custom memory allocators (`mlock`, `explicit_bzero`) would be implemented to prevent string retention in RAM.

---

## 🚀 Quick Start

### Prerequisites
- C++17 Compiler (GCC/Clang)
- CMake 3.10+
- OpenSSL Development Headers
- *Optional:* `tpm2-tools` and `libsecret-tools` 

### Build

```bash
mkdir build && cd build
cmake ..
make
```

### Usage

```bash
# Create a new encrypted vault
./passwordManager create myVault

# Store a credential
./passwordManager add myVault github_token

# Retrieve a credential
./passwordManager view myVault github_token

# Note: All commands securely prompt for passwords without echoing to the terminal.
```

## 🛠️ Project Structure

```text
src/
├── main.cpp                 # CLI argument parsing and strict POSIX terminal control
├── tools/
│   ├── Manager.cpp          # Vault lifecycle and AES payload serialization
│   ├── Accounts.cpp         # LocalAccount implementation and PBKDF2 derivation
│   └── MasterKeyManager.cpp # TPM/libsecret sealing and hardware boundaries
└── encryption/
    └── Encryption.cpp       # OpenSSL EVP abstractions and RAII memory cleanup
```

---
<p align="center">Built for performance, engineered for security.</p>
