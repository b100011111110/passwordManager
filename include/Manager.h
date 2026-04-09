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

// Helper functions for encryption selection
string getEncryptionTypeFromConfig();
void saveEncryptionTypeToConfig(const string& encType);
Encryption* createEncryptionObject(const string& type);

class PasswordManager {
private:
    std::map<string, Account*> accounts;
    Encryption* encryptionStandard;

    void loadExistingAccounts();
    void saveAccountMetadata();

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

    bool createAccount(string accName, string accPass, string encryptionType);

    bool deleteAccount(string accName, string accPass);

    void addPassword(string accName, string accPass, string user, string pass);

    bool deletePassword(string accName, string accPass, string user);

    bool viewPasswords(string accName, string accPass, string user);

    bool setEncryption(string encryptionType);

    string getEncryption() const;

    ~PasswordManager();

    // We will add the rest of the methods in Stage 2
};

#endif