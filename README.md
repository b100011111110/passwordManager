# 🔐 PasswordMgr

> A professional-grade, CLI-based password manager written in modern C++ — built with encryption, clean OOP design, and local-first storage.

---

## Overview

**PasswordMgr** is a command-line password management tool built entirely in C++. It allows users to securely store, retrieve, and manage credentials in encrypted local storage. Each account holds username-password pairs that are encrypted before being written to disk, ensuring your data is never stored in a human-readable format.

This project is designed as a structured learning journey through professional C++ development — covering object-oriented principles, encryption, file I/O, CLI design.

---

## Features

| Feature | Description |
|---|---|
| `add-account` | Create a new named account protected by a master password |
| `delete-account` | Remove an account and all its stored credentials |
| `add-password` | Store a username-password pair inside an account |
| `delete-password` | Remove a specific credential entry from an account |
| `fetch-password` | Retrieve a stored password for a given user ID |
| Encryption | All data is encrypted before being written to disk |
| Local Storage | No cloud, no internet — everything lives on your machine |
| Unrecognizable Storage Format | The storage file is binary-encrypted and not human-readable |

---

## Usage

```bash
# Create a new account
passwordMgr add-account <accountName> <accountPassword>

# Delete an existing account
passwordMgr delete-account <accountName> <accountPassword>

# Add a credential to an account
passwordMgr add-password <accountName> <accountPassword> <userId> <password>

# Delete a credential from an account
passwordMgr delete-password <accountName> <accountPassword> <userId>

# Fetch a credential from an account
passwordMgr fetch-password <accountName> <accountPassword> <userId>
```

### Examples

```bash
$ passwordMgr add-account myVault myMasterPass123
✔ Account 'myVault' created successfully.

$ passwordMgr add-password myVault myMasterPass123 github myGithubPass!
✔ Password for 'github' added to account 'myVault'.

$ passwordMgr fetch-password myVault myMasterPass123 github
✔ Password for 'github': myGithubPass!

$ passwordMgr delete-password myVault myMasterPass123 github
✔ Password for 'github' deleted from account 'myVault'.

$ passwordMgr delete-account myVault myMasterPass123
✔ Account 'myVault' deleted successfully.
```

---

## Project Architecture

```
passwordMgr/
├── src/
│   ├── main.cpp                  # Entry point, CLI argument parsing
│   ├── cli/
│   │   ├── CommandParser.h/.cpp  # Parses and validates CLI input
│   │   └── CommandRouter.h/.cpp  # Routes commands to handlers
│   ├── core/
│   │   ├── Account.h/.cpp        # Account class — holds credentials
│   │   ├── Credential.h/.cpp     # Credential struct — userId + password pair
│   │   ├── Manager.h/.cpp        # Central manager — orchestrates operations
│   │   └── IStorage.h            # Abstract storage interface
│   ├── storage/
│   │   ├── FileStorage.h/.cpp    # Concrete file-based storage implementation
│   │   └── StorageSerializer.h   # Handles binary serialization/deserialization
│   ├── encryption/
│   │   ├── IEncryptor.h          # Abstract encryption interface
│   │   ├── AESEncryptor.h/.cpp   # AES encryption implementation
│   │   └── KeyDerivation.h/.cpp  # Derives encryption keys from passwords
│   └── utils/
│       ├── Logger.h/.cpp         # Minimal logging utility
│       └── ErrorHandler.h/.cpp   # Centralized error handling
├── tests/
│   ├── test_account.cpp
│   ├── test_storage.cpp
│   └── test_encryption.cpp
├── data/
│   └── .vault                    # Encrypted local storage file (auto-generated)
├── CMakeLists.txt
├── .gitignore
└── README.md
```

---

## OOP & C++ Concepts Used

This project is intentionally designed to demonstrate the following C++ and software engineering concepts:

| Concept | Where It Appears |
|---|---|
| **Structs** | `Credential` — lightweight data holder for userId + password |
| **Classes** | `Account`, `Manager`, `FileStorage`, `AESEncryptor` |
| **Abstract Classes** | `IStorage`, `IEncryptor` — pure virtual interfaces |
| **Polymorphism** | `Manager` operates on `IStorage*` and `IEncryptor*` — swappable implementations |
| **Encapsulation** | Private members with controlled access in all core classes |
| **Inheritance** | `FileStorage : IStorage`, `AESEncryptor : IEncryptor` |
| **RAII** | File handles and resources managed with scope-based lifetimes |
| **Templates** | Utility helpers for serialization |
| **Error Handling** | Custom exceptions with clear error messages |
| **STL Containers** | `std::map`, `std::vector`, `std::string` throughout |

---

## Encryption Design

- Account passwords are never stored directly. They are passed through a **key derivation function (KDF)** to produce an encryption key.
- All stored data is encrypted using **AES-256** (via OpenSSL or a lightweight bundled library).
- The storage file (`.vault`) is written in a **binary encrypted format** — it is unreadable without the correct account password.
- Each account is independently encrypted — compromising one account does not expose others.

> ⚠️ If you forget your account password, your stored credentials **cannot be recovered**. There is no backdoor by design.

### Prerequisites

- C++17 or later
- CMake 3.15+
- OpenSSL (for AES encryption)

### Building

```bash
git clone https://github.com/yourusername/passwordMgr.git
cd passwordMgr
mkdir build && cd build
cmake ..
make
```

### Running

```bash
./passwordMgr add-account myVault myMasterPass123
```

### Running Tests

```bash
cd build
ctest --output-on-failure
```

---

## Security Notes

- Passwords are **never logged** or printed to stdout beyond explicit `fetch-password` calls.
- The vault file is stored at a configurable path (default: `~/.passwordMgr/.vault`).
- This project is intended as a **learning tool and personal utility**. For production use, consider auditing the cryptographic implementation.

---

## Contributing

This project follows a stage-based development model. Contributions, suggestions, and code reviews are welcome after Stage 10 is complete.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit with clear messages: `git commit -m "feat: add AES key derivation"`
4. Open a pull request with a description of changes

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Built with C++ · Encrypted · Local-first · No telemetry</p>
