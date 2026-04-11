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
| **PBKDF2 Key Derivation** | Passwords are derived using PBKDF2 (200k iterations, SHA256) |
| **Per-Vault Random Salt** | Each vault has unique random 16-byte salt stored plaintext |
| **Random IV Per Operation** | Each encryption generates new random 16-byte IV |
| **Magic Header Authentication** | "PMGR" header validates correct password on vault load |
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

# Note: AES-256 is the only supported encryption method
```

### Examples

```bash
# Create account with AES-256 encryption
$ ./passwordManager create myVault
Enter account password: 
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

### Full-File Encryption
- **Complete vault protection**: The entire vault file (containing all IDs and passwords) is encrypted as a single unit using the account password as the encryption key.
- **ID protection**: Credential IDs (like `sh1:xxxx...`) are encrypted along with their passwords — not stored in plain text.
- **Metadata encryption**: Account information is stored in an encrypted `accounts.init` file using a master key.

### Encryption Mechanism
- Account passwords are derived using **PBKDF2** (200,000 iterations, SHA256) with a unique per-vault random salt.
  - **Salt**: 16 random bytes generated on first save, stored plaintext at vault file start (non-secret, prevents precomputed attacks).
  - **Key Derivation**: PBKDF2(password, vault_salt, 200k, SHA256) → 32-byte AES key
- All vault data is serialized to **JSON format** with magic header "PMGR", then encrypted using **AES-256-CBC**:
  - **IV**: 16 random bytes (RAND_bytes) generated per operation, prepended to ciphertext
  - **Algorithm**: AES-256-CBC via OpenSSL EVP interface
  - **Validation**: Magic header check detects wrong password immediately on load
- The vault file (e.g., `273bb8988bc9eff3f945e81f4f9caee5d8e67d785b4078773e39ca84fc99f9b6.json`) is written in **pure binary encrypted format** — completely unreadable without the correct account password.
- Each account is independently encrypted with unique salt — compromising one account's password does not expose others.

### File Structure
```
accounts.init          (encrypted account metadata with id1 identifiers)
<hashed-filename>.json (vault file: [16-byte salt] + AES_encrypt(PMGR + JSON))
config.json            (unencrypted encryption type preference)
```

Vault file binary layout:
- **Bytes 0-15**: Random salt (16 bytes, plaintext)
- **Bytes 16+**: AES-256-CBC encrypted blob containing:
  - Magic header: "PMGR" (4 bytes)
  - Vault JSON data (credential entries)
  - IV prepended to ciphertext and hex-encoded

> ⚠️ If you forget your account password, your stored credentials **cannot be recovered**. There is no backdoor by design.

---

## Prerequisites

- C++17 or later
- CMake 3.10+
- OpenSSL (for encryption)
- nlohmann/json (for JSON handling)

## Building

```bash
mkdir -p build && cd build
cmake ..
make
```

The executable will be at `build/passwordManager`.

## Running

```bash
# Create a new account
./build/passwordManager create myAccount

# Add a credential
./build/passwordManager add myAccount myId

# View a credential
./build/passwordManager view myAccount myId

# Remove a credential
./build/passwordManager remove myAccount myId

# Delete account
./build/passwordManager delete myAccount
```

---

## Security Notes

- **Passwords are never logged** or printed to stdout beyond explicit `view` commands.
- **Credential IDs are encrypted** in the vault file alongside their passwords.
- **Account metadata is encrypted** in `accounts.init`, including any associated identifiers like `id1`.
- **Full-file encryption** ensures the entire vault is encrypted as a single unit — no component is readable without the correct password.
- **PBKDF2 derivation** with 200k iterations prevents brute-force password guessing attacks.
- **Per-vault salt** unique to each vault prevents precomputed rainbow table attacks.
- **Random IV per operation** ensures identical plaintexts produce different ciphertexts.
- **Magic header validation** ("PMGR") detects wrong password without storing password derivatives.
- **No password secrets stored** — accounts.init contains zero password-derived information.
- Vault files are stored with **restrictive file permissions (0600)** — only the owner can read/write.
- This project is intended as a **learning tool and personal utility**. For production use, consider auditing the cryptographic implementation and conducting a security audit.

---

## Recent Changes

### v3.0 (Current) — Security & Simplification
- ✓ **PBKDF2 key derivation** — passwords derived with 200k iterations, SHA256
- ✓ **Per-vault random salt** — unique 16-byte salt generated, stored plaintext at vault start
- ✓ **Random IV per operation** — new 16-byte IV (RAND_bytes) for every encryption
- ✓ **Magic header validation** — "PMGR" header detects wrong password immediately
- ✓ **AES-256-CBC only** — simplified to focused, secure single algorithm (removed RSA/DES)
- ✓ **Encrypted validation** — passwords never checked against stored derivatives
- ✓ **Codebase simplification** — 50% reduction in encryption code, removed 230+ lines of RSA/DES

### v2.0
- ✓ **Full vault file encryption** — entire vault is encrypted, not just individual passwords
- ✓ **ID encryption** — credential IDs (including those with colons like `sh1:xxxx`) are encrypted
- ✓ **Encrypted metadata** — account information with `id1` identifiers is encrypted in `accounts.init`
- ✓ **Fixed segmentation fault** — proper cleanup of encryption objects
- ✓ **Hashed vault filenames** — account vault files use SHA256 hashed names for privacy

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
