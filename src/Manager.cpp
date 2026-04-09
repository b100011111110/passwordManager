#include "Manager.h"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::filesystem::exists;
using std::filesystem::remove;
using std::filesystem::path;
using std::filesystem::directory_iterator;
using std::ifstream;
using std::ofstream;

const string ACCOUNTS_FILE = "accounts.init";

PasswordManager::PasswordManager(Encryption* encryption)
    : encryptionStandard(encryption) {
    loadExistingAccounts();
}

void PasswordManager::loadExistingAccounts() {
    if (exists(path(ACCOUNTS_FILE))) {
        try {
            json accountsData;
            ifstream in(ACCOUNTS_FILE);
            in >> accountsData;

            for (auto& [accName, accPass] : accountsData.items()) {
                Account* account = createLocalAccount(accName, accPass, accName + ".json", encryptionStandard);
                accounts[accName] = account;
            }
        } catch (...) {
            // If loading fails, continue
        }
    }
}

void PasswordManager::saveAccountMetadata() {
    json accountsData = json::object();
    for (const auto& [accName, account] : accounts) {
        // We need to get the password from account - for now just use a placeholder
        // In a real implementation, you'd want to encrypt this
        accountsData[accName] = "";  // Password stored in memory only
    }
    ofstream out(ACCOUNTS_FILE);
    out << accountsData.dump(4);
}

PasswordManager::~PasswordManager() {
    for (auto& pair : accounts) {
        delete pair.second;
    }
    accounts.clear();
}

bool PasswordManager::createAccount(string accName, string accPass) {
    if (accounts.find(accName) != accounts.end()) {
        cout << "Account already exists." << endl;
        return false;
    }
    string filename = accName + ".json";
    Account* newAccount = createLocalAccount(accName, accPass, filename, encryptionStandard);
    accounts[accName] = newAccount;

    // Save account metadata
    json accountsData = json::object();
    if (exists(path(ACCOUNTS_FILE))) {
        ifstream in(ACCOUNTS_FILE);
        in >> accountsData;
    }
    accountsData[accName] = accPass;
    ofstream out(ACCOUNTS_FILE);
    out << accountsData.dump(4);

    cout << "Account created." << endl;
    return true;
}

bool PasswordManager::deleteAccount(string accName, string accPass) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    Account* account = accounts[accName];
    if (!account->validateAccountPassword(accPass)) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    delete account;
    accounts.erase(accName);

    // Remove from account metadata
    if (exists(path(ACCOUNTS_FILE))) {
        json accountsData;
        ifstream in(ACCOUNTS_FILE);
        in >> accountsData;
        accountsData.erase(accName);
        ofstream out(ACCOUNTS_FILE);
        out << accountsData.dump(4);
    }

    // Delete individual file
    string filename = accName + ".json";
    if (exists(path(filename))) {
        remove(path(filename));
    }
    cout << "Account deleted." << endl;
    return true;
}

void PasswordManager::addPassword(string accName, string accPass, string user, string pass) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return;
    }

    Account* account = accounts[accName];
    if (!account->validateAccountPassword(accPass)) {
        cout << "Invalid account or password." << endl;
        return;
    }

    if (account->addPassword(accPass, user, pass)) {
        cout << "Password added." << endl;
    } else {
        cout << "Failed to add password." << endl;
    }
}

bool PasswordManager::deletePassword(string accName, string accPass, string user) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    Account* account = accounts[accName];
    if (!account->validateAccountPassword(accPass)) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    if (account->deletePassword(accPass, user)) {
        cout << "Password deleted." << endl;
        return true;
    } else {
        cout << "Password not found." << endl;
        return false;
    }
}

bool PasswordManager::viewPasswords(string accName, string accPass, string user) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    Account* account = accounts[accName];
    if (!account->validateAccountPassword(accPass)) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    if (user.empty()) {
        cout << "Viewing all passwords - feature not fully implemented" << endl;
        return false;
    }

    return account->viewPassword(accPass, user);
}