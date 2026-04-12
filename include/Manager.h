#ifndef MANAGER_H
#define MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "Accounts.h"
#include "encryption.h"

// Account metadata structure (no plaintext passwords stored)
struct AccountMeta {
    std::string accountName;
    std::string hashedFilename;
    std::string encryptionType;
};

// Helper functions for encryption selection
std::string getEncryptionTypeFromConfig();
void saveEncryptionTypeToConfig(const std::string& encType);
std::unique_ptr<Encryption> createEncryptionObject(const std::string& type);

class PasswordManager {
private:
    std::map<std::string, AccountMeta> accounts;  // Changed from Account* to AccountMeta
    std::unique_ptr<Encryption> encryptionStandard;
    std::vector<unsigned char> masterKey;

    void loadExistingAccounts();
    void saveAccountMetadata();

    // Account data encryption/decryption using hardware-protected master key
    std::string encryptAccountsData(const std::string& plaintext);
    std::string decryptAccountsData(const std::string& ciphertext);

public:
    PasswordManager(std::unique_ptr<Encryption> encryption);

    /*
    this is a class that will manage the password manager,
    it will have methods to
        create accounts,
        delete accounts,
        add passwords,
        delete passwords,
        view passwords
    */

    bool createAccount(std::string accName, std::string accPass, std::string encryptionType);

    bool deleteAccount(std::string accName, std::string accPass);

    void addPassword(std::string accName, std::string accPass, std::string user, std::string pass);

    bool deletePassword(std::string accName, std::string accPass, std::string user);

    bool viewPasswords(std::string accName, std::string accPass, std::string user);

    bool setEncryption(std::string encryptionType);

    std::string getEncryption() const;

    ~PasswordManager() = default;

    // We will add the rest of the methods in Stage 2
};

#endif