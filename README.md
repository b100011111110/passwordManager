# 🔐 Password Manager

> A professional-grade, CLI-based password manager written in C++ that enforces full-file encryption, clean architectural design, and a strictly local-first storage model.

---

## 📖 Overview

**Password Manager** is a robust command-line interface (CLI) application built entirely in C++ that allows users to securely store, retrieve, and manage their credentials. It was designed from the ground up to demonstrate proficiency in **software architecture, applied cryptography, and systems programming**. 

Unlike conventional managers that might store data in localized SQLite databases or easily exposed plaintext formats, this tool encrypts the *entire* storage backend. By leveraging OpenSSL and robust key derivation techniques, it ensures that your secrets—and the metadata associated with them—never touch the disk in an unprotected state. 

Whether you are here to review the codebase from an engineering perspective or looking to secure personal credentials safely, this project serves as a practical implementation of **modern C++ guidelines** and **industry-standard security practices**.

---

## ✨ Key Features

- **🛡️ Full-File Encryption**: The entire vault data, including your sensitive credential IDs and structural formatting, is rigorously encrypted as a single binary blob using **AES-256-CBC**.
- **🔑 Strong Key Derivation**: Master passwords are never recorded or stored. The system derives a 256-bit cryptographic key via **PBKDF2-SHA256** utilizing 200,000 iterations to heavily mitigate brute-force attacks.
- **🎲 Cryptographic Randomness**: A unique, per-vault 16-byte random salt is generated on creation to defeat rainbow tables. Furthermore, a fresh, truly random 16-byte Initialization Vector (IV) is utilized for *every* individual encryption operation.
- **✅ Magic Header Validation**: Instead of comparing hashes to verify your credentials, the system attempts a live decryption of the vault. If the decrypted payload starts with the correct `PMGR` magic header, access is granted. Otherwise, it safely and instantly rejects the attempt.
- **🕵️ Metadata Obfuscation**: Vault files are assigned **SHA-256 hashed filenames**. An attacker scanning the filesystem cannot map a given database file back to a specific user's account name.
- **💻 Local-First Storage**: Zero telemetry analytics, no internet synchronization, and no external points of failure. Everything resides strictly on your machine.

---

## 🧠 Architecture & How it Works

At its core, this project demonstrates how to safely manage sensitive user data within memory constraints and how to interact securely with low-level file I/O operations. Here is a brief look at the data lifecycle:

### 1. Storage Structure
Credentials are never stored in structured plaintext. They are dynamically populated into a serialized JSON payload using `nlohmann/json`. This structured format is then packaged entirely, encrypted, and flushed directly to disk as a raw binary blob, providing absolutely no human-readable context to external applications.

### 2. Encryption and Authentication Pipeline
When you initialize an account and save data:
1. **Salt Generation**: The core runtime securely generates a 16-byte random salt using `RAND_bytes`.
2. **Key Derivation**: When unlocking the vault, the user submits their master password. The software combines this with the file’s 16-byte salt and processes it through the PBKDF2 algorithm, deterministically returning a 256-bit AES cryptographic key.
3. **Payload Construction**: The system prepends the `PMGR` magic header to the serialized credentials, and allocates a freshly generated 16-byte IV.
4. **AES-256 Encryption**: The total payload is passed through the OpenSSL `EVP` interface, returning the encrypted buffer that is committed to disk.

When you attempt to read from the account, the manager derives the key directly from the terminal input and attempts decryption. If the magic header `PMGR` does not align within the first 4 bytes of memory, the routine immediately halts.

---

## 🚀 Getting Started

### Prerequisites
To build and evaluate this project, you will need:
- A C++ compiler with **C++17** support or later (e.g., GCC, Clang)
- **CMake** (v3.10+) 
- **OpenSSL** (core dependency for AES components and safe randomness)
- **nlohmann/json** (widely supported modern JSON library for C++)

### Compilation 
This codebase utilizes CMake to enforce a clean and consistent cross-platform build process.
```bash
# Clone the repository and navigate into the root directory
mkdir -p build && cd build

# Configure and compile the project binary
cmake ..
make
```

### Usage Instructions
Once compiled successfully, the executable will be placed inside your `build` directory. Here is how you can interact with the CLI to manage your encrypted vaults.

#### Initializing an Account
Create a new secure vault. The exact vault username remains obscured on-disk via SHA-256 hashing.
```bash
./build/passwordManager create <accountName>
```

#### Storing a Credential
Add an identification string (e.g., an email address, username, or unique ID) and securely store the associated password inside the vault.
```bash
./build/passwordManager add <accountName> <credentialID>
```
*Note: The CLI will safely intercept your input, prompting you without screen echo to enter your vault master password and your newly targeted password.*

#### Retrieving a Credential
Decrypt the vault directly into memory and extract your saved password string securely to the terminal.
```bash
./build/passwordManager view <accountName> <credentialID>
```

#### Removing a Credential
Cleanly erase a specific credential record from your vault, actively regenerating the file's binary signature with a new IV.
```bash
./build/passwordManager remove <accountName> <credentialID>
```

#### Deleting an Account
Completely and permanently shred your vault and all of its associated encrypted credentials from the filesystem.
```bash
./build/passwordManager delete <accountName>
```

> **⚠️ Warning:** Because this tool acts with a strictly local-first and uncompromising encryption design, forgetting your master password means **your data cannot be recovered**. There are explicitly no hidden backdoors.

---
