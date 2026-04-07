#include <iostream>
#include <string>
#include <vector>
#include "encryption.h"

#include "Accounts.h"

using std::vector;
using std::string;
using std::cout;
using std::endl;


class LocalAccount : public Account {
/*
    this is a class that is an implementation of the Account class
    it will represent a local account that will store the passwords in a file
*/

    string password;
    string filePath;
    string encryptionKey;
    Encryption* encryptionStandard;
    vector<string> vault;
public:
    string username;
    LocalAccount(string user, string pass, string file, Encryption* type) {
        this->username = user;
        this->password = pass;
        this->filePath = file;
        this->encryptionKey = pass;
        this->encryptionStandard = type;
    }
    
    bool validateAccountPassword(string pass) override {
        return pass == this->password;
    }

    string encryptPassword(string pass) override {
        if (this->encryptionStandard == nullptr) return;
        string encryptedPass = this->encryptionStandard->encrypt(pass, this->encryptionKey);
        return encryptedPass;
    }

    string decryptPassword(string pass) override {
        // Implement decryption logic here
        if (this->encryptionStandard == nullptr) return;
        string decryptedPass = this->encryptionStandard->decrypt(pass, this->encryptionKey);
        return decryptedPass;
    }

    bool addPassword(string userPassword,string id,string idPassword) override {
        if (!validateAccountPassword(userPassword)) {
            return false; // Invalid account password
        }
        string encryptedIdPassword = encryptPassword(idPassword);
        vault.push_back(id + ":" + encryptedIdPassword);
        return true;
    }

    bool deletePassword(string userPassword,string id) override {
        if (!validateAccountPassword(userPassword)) {
            return false; // Invalid account password
        }
        for (auto it = vault.begin(); it != vault.end(); ++it) {
            if (it->substr(0, it->find(':')) == id) {
                vault.erase(it);
                return true; // Password deleted successfully
            }
        }
        return false; // ID not found
    }

    bool viewPassword(string userPassword,string id) override {
        if (!validateAccountPassword(userPassword)) {
            return false; // Invalid account password
        }
        for (const auto& entry : vault) {
            if (entry.substr(0, entry.find(':')) == id) {
                // Found the entry, now decrypt and return the password
                string encryptedPassword = entry.substr(entry.find(':') + 1);
                cout<< "Password for " << id << ": " << decryptPassword(encryptedPassword) << endl;
                return true; // Password viewed successfully
            }
        }
        return false; // ID not found
    }

};