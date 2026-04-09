#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include "encryption.h"
#include "Accounts.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;
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
        vault.push_back(id + "|" + encryptedIdPassword);
        saveVault();
        return true;
    }

    bool deletePassword(string userPassword, string id) override {
        if (!validateAccountPassword(userPassword)) {
            return false;
        }
        for (auto it = vault.begin(); it != vault.end(); ++it) {
            if (it->substr(0, it->find('|')) == id) {
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
            if (entry.substr(0, entry.find('|')) == id) {
                string encryptedPassword = entry.substr(entry.find('|') + 1);
                cout << "Password for " << id << ": " << decryptPassword(encryptedPassword) << endl;
                return true;
            }
        }
        return false;
    }

private:
    void saveVault() {
        // Create JSON array of entries
        json vaultData = json::array();
        for (const auto& entry : vault) {
            vaultData.push_back(entry);
        }

        // Serialize to string
        string plaintextJson = vaultData.dump();

        // Encrypt entire file
        string encryptedData = encryptPassword(plaintextJson);

        // Write encrypted data
        ofstream out(filePath, std::ios::binary);
        if (!out) return;
        out.write(encryptedData.c_str(), encryptedData.length());
        out.close();
    }

    void loadVault() {
        ifstream in(filePath, std::ios::binary);
        if (!in) return;

        // Read encrypted data
        string encryptedData((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        in.close();

        if (encryptedData.empty()) return;

        try {
            // Decrypt entire file
            string decryptedData = decryptPassword(encryptedData);

            // Parse JSON
            json vaultData = json::parse(decryptedData);

            vault.clear();
            for (const auto& entry : vaultData) {
                vault.push_back(entry.get<string>());
            }
        } catch (...) {
            vault.clear();
        }
    }
};

// Factory function to create a LocalAccount
Account* createLocalAccount(string user, string pass, string file, Encryption* type) {
    return new LocalAccount(user, pass, file, type);
}