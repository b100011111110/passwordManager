#ifndef MANAGER_H
#define MANAGER_H

#include <iostream>
#include <string>
#include <map>
#include <memory>
#include "Accounts.h"
#include "encryption.h"

using std::string;
using std::cout;
using std::endl;

// Account metadata structure (no plaintext passwords stored)
struct AccountMeta {
    string accountName;
    string hashedFilename;
    string encryptionType;
    string id1;  // Additional identifier if needed
};

// Helper functions for encryption selection
string getEncryptionTypeFromConfig();
void saveEncryptionTypeToConfig(const string& encType);
Encryption* createEncryptionObject(const string& type);

class PasswordManager {
private:
    std::map<string, AccountMeta> accounts;  // Changed from Account* to AccountMeta
    Encryption* encryptionStandard;

    void loadExistingAccounts();
    void saveAccountMetadata();
    string getEncryptedFilename(const string& accountName);  // New: get hashed filename

public:
    PasswordManager(Encryption* encryption);

    /*
    this is a class that will manage the password manager,
    it will have methods to
        create accounts,
        delete accounts,
        add passwords,
        delete passwords,
        view passwords
    */

    bool createAccount(string accName, string accPass, string encryptionType, string id1 = "");

    bool deleteAccount(string accName, string accPass);

    void addPassword(string accName, string accPass, string user, string pass);

    bool deletePassword(string accName, string accPass, string user);

    bool viewPasswords(string accName, string accPass, string user);

    bool setEncryption(string encryptionType);

    string getEncryption() const;

    ~PasswordManager();  // No longer needs to delete Account* objects

    // We will add the rest of the methods in Stage 2
};

#endif