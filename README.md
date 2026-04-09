# 🔐 Password Manager

> A professional-grade, CLI-based password manager written in modern C++ — built with full-file encryption, clean OOP design, and local-first storage.

---

## Overview

**PasswordManager** is a command-line password management tool built entirely in C++. It allows users to securely store, retrieve, and manage credentials with **full-file encryption**. Each account holds ID-password pairs that are encrypted alongside the entire vault file before being written to disk, ensuring your data is never stored in a human-readable format.

This project is designed as a structured learning journey through professional C++ development — covering object-oriented principles, encryption, file I/O, CLI design, and secure data handling.

---

## Features

| Feature | Description |
|---|---|
| `create` | Create a new named account protected by a master password |
| `delete` | Remove an account and all its stored credentials |
| `add` | Store an ID-password pair inside an account |
| `remove` | Remove a specific credential entry from an account |
| `view` | Retrieve and display a stored password for a given ID |
| **Full-File Encryption** | Entire vault file is encrypted with account password (AES-256) |
| **Encrypted Metadata** | Account metadata (including `id1` identifiers) is encrypted |
| Multiple Encryption Types | Support for AES, RSA, and DES encryption algorithms |
| Local Storage | No cloud, no internet — everything lives on your machine |
| Binary Encryption Format | The storage file is completely encrypted and not human-readable |

---

## Usage

### Commands

```bash
# Create a new account (will prompt for password and encryption type)
./passwordManager create <accountName>

# Delete an existing account (will prompt for password)
./passwordManager delete <accountName>

# Add a credential to an account (will prompt for passwords)
./passwordManager add <accountName> <id>

# Remove a credential from an account (will prompt for password)
./passwordManager remove <accountName> <id>

# View a stored credential (will prompt for password, then display the password)
./passwordManager view <accountName> <id>

# Set encryption type for new accounts
./passwordManager config encryption [aes|rsa|des]
```

### Examples

```bash
# Create account with AES encryption
$ ./passwordManager create myVault
Enter account password: 
Select encryption type:
1. AES
2. RSA
3. DES
Enter choice (1-3): 1
Account created with aes encryption (encrypted vault filename).
Account created successfully!

# Add a credential with ID
$ ./passwordManager add myVault "sh1:08c04eef88649ce2811ce0f447509fe30a05b2c6"
Enter account password: 
Enter password for user 'sh1:08c04eef88649ce2811ce0f447509fe30a05b2c6': 
Password added.

# View the credential
$ ./passwordManager view myVault "sh1:08c04eef88649ce2811ce0f447509fe30a05b2c6"
Enter account password: 
Password for sh1:08c04eef88649ce2811ce0f447509fe30a05b2c6: (displays decrypted password)

# Remove a credential
$ ./passwordManager remove myVault "sh1:08c04eef88649ce2811ce0f447509fe30a05b2c6"
Enter account password: 
Password deleted.

# Delete entire account
$ ./passwordManager delete myVault
Enter account password: 
Account deleted.
```


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
