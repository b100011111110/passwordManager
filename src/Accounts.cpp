#include <iostream>
#include <fstream>
#include <vector>
#include "encryption.h"
#include "Accounts.h"

using std::vector;
using std::string;
using std::cout;
using std::endl;
using std::ofstream;
using std::ifstream;
using std::getline;

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

    LocalAccount(string user, string pass, string file, Encryption* type)
        : username(user), password(pass), filePath(file), encryptionKey(pass), encryptionStandard(type) {
        loadVault();
    }

    virtual ~LocalAccount() {
        saveVault();
    }

    bool validateAccountPassword(string pass) override {
        return pass == this->password;
    }

    string encryptPassword(string pass) override {
        if (this->encryptionStandard == nullptr) return "";
        string encryptedPass = this->encryptionStandard->encrypt(pass, this->encryptionKey);
        return encryptedPass;
    }

    string decryptPassword(string pass) override {
        if (this->encryptionStandard == nullptr) return "";
        string decryptedPass = this->encryptionStandard->decrypt(pass, this->encryptionKey);
        return decryptedPass;
    }

    bool addPassword(string userPassword, string id, string idPassword) override {
        if (!validateAccountPassword(userPassword)) {
            return false;
        }
        string encryptedIdPassword = encryptPassword(idPassword);
        vault.push_back(id + ":" + encryptedIdPassword);
        saveVault();
        return true;
    }

    bool deletePassword(string userPassword, string id) override {
        if (!validateAccountPassword(userPassword)) {
            return false;
        }
        for (auto it = vault.begin(); it != vault.end(); ++it) {
            if (it->substr(0, it->find(':')) == id) {
                vault.erase(it);
                saveVault();
                return true;
            }
        }
        return false;
    }

    bool viewPassword(string userPassword, string id) override {
        if (!validateAccountPassword(userPassword)) {
            return false;
        }
        for (const auto& entry : vault) {
            if (entry.substr(0, entry.find(':')) == id) {
                string encryptedPassword = entry.substr(entry.find(':') + 1);
                cout << "Password for " << id << ": " << decryptPassword(encryptedPassword) << endl;
                return true;
            }
        }
        return false;
    }

private:
    void saveVault() {
        ofstream out(filePath);
        if (!out) return;
        for (const auto& entry : vault) {
            out << entry << endl;
        }
    }

    void loadVault() {
        ifstream in(filePath);
        if (!in) return;
        string line;
        vault.clear();
        while (getline(in, line)) {
            if (!line.empty()) {
                vault.push_back(line);
            }
        }
    }
};

// Factory function to create a LocalAccount
Account* createLocalAccount(string user, string pass, string file, Encryption* type) {
    return new LocalAccount(user, pass, file, type);
}