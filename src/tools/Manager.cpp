#include "Manager.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

using json = nlohmann::json;
using std::filesystem::exists;
using std::filesystem::remove;
using std::filesystem::path;
using std::filesystem::directory_iterator;
using std::ifstream;
using std::ofstream;

const string ACCOUNTS_FILE = "accounts.init";
const string CONFIG_FILE = "config.json";

// Master encryption key for accounts file (in production, derive from master password)
const string ACCOUNTS_MASTER_KEY = "PasswordManager2024SecureKey!";

// Set restrictive file permissions (0600 = owner read/write only)
void setSecureFilePermissions(const string& filename) {
    chmod(filename.c_str(), S_IRUSR | S_IWUSR);  // 0600
}

// Encrypt accounts data using AES
string encryptAccountsData(const string& plaintext) {
    AESEncryption aes;
    // For accounts file, we use a fixed master key derived from ACCOUNTS_MASTER_KEY
    string encrypted = aes.encrypt(plaintext, ACCOUNTS_MASTER_KEY);
    return encrypted;
}

// Decrypt accounts data using AES
string decryptAccountsData(const string& ciphertext) {
    AESEncryption aes;
    string decrypted = aes.decrypt(ciphertext, ACCOUNTS_MASTER_KEY);
    return decrypted;
}

// Generate SHA256 hash of account name for encrypted filename
string hashAccountName(const string& accountName) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (unsigned char*)accountName.c_str(), accountName.length());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str() + ".json";
}

string getEncryptionTypeFromConfig() {
    if (exists(path(CONFIG_FILE))) {
        try {
            json config;
            ifstream in(CONFIG_FILE);
            in >> config;
            if (config.contains("encryptionType")) {
                return config["encryptionType"].get<string>();
            }
        } catch (...) {
            // If config load fails, use default
        }
    }
    return "aes";  // Default to AES
}

void saveEncryptionTypeToConfig(const string& encType) {
    json config;
    if (exists(path(CONFIG_FILE))) {
        try {
            ifstream in(CONFIG_FILE);
            in >> config;
        } catch (...) {
            config = json::object();
        }
    } else {
        config = json::object();
    }
    config["encryptionType"] = encType;
    ofstream out(CONFIG_FILE);
    out << config.dump(4);
}

Encryption* createEncryptionObject(const string& type) {
    // Only AES encryption is supported
    return new AESEncryption();
}

PasswordManager::PasswordManager(Encryption* encryption)
    : encryptionStandard(encryption) {
    loadExistingAccounts();
}

string PasswordManager::getEncryptedFilename(const string& accountName) {
    return hashAccountName(accountName);
}

void PasswordManager::loadExistingAccounts() {
    if (exists(path(ACCOUNTS_FILE))) {
        try {
            // Read encrypted data from file
            std::ifstream infile(ACCOUNTS_FILE, std::ios::binary);
            std::string encryptedData((std::istreambuf_iterator<char>(infile)),
                                      std::istreambuf_iterator<char>());
            infile.close();

            // Decrypt the data
            string decrypted = decryptAccountsData(encryptedData);

            // Parse JSON
            json accountsData = json::parse(decrypted);

            for (auto& [accName, accInfo] : accountsData.items()) {
                string accPass;
                string encryption = "aes";  // default
                string id1 = "";  // id1 identifier

                // Handle both old format (string) and new format (object)
                if (accInfo.is_string()) {
                    accPass = accInfo.get<string>();
                } else if (accInfo.is_object()) {
                    accPass = accInfo["password"].get<string>();
                    if (accInfo.contains("encryption")) {
                        encryption = accInfo["encryption"].get<string>();
                    }
                    if (accInfo.contains("id1")) {
                        id1 = accInfo["id1"].get<string>();
                    }
                }

                // Use hashed filename
                string hashedFilename = hashAccountName(accName);
                try {
                    Account* account = createLocalAccount(accName, accPass, hashedFilename, encryptionStandard);
                    accounts[accName] = account;
                } catch (const std::runtime_error& e) {
                    // Wrong password or decryption error - skip loading this account
                    cout << "Warning: Could not load account '" << accName << "': " << e.what() << endl;
                }
            }
        } catch (...) {
            // If loading fails, continue
            cout << "Warning: Could not load existing accounts." << endl;
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

bool PasswordManager::createAccount(string accName, string accPass, string encryptionType, string id1) {
    if (accounts.find(accName) != accounts.end()) {
        cout << "Account already exists." << endl;
        return false;
    }

    // Only AES encryption is supported
    string type = "aes";
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    // Use hashed filename for encryption
    string hashedFilename = hashAccountName(accName);
    try {
        Account* newAccount = createLocalAccount(accName, accPass, hashedFilename, encryptionStandard);
        accounts[accName] = newAccount;
    } catch (const std::runtime_error& e) {
        cout << "Failed to create account: " << e.what() << endl;
        return false;
    }

    // Save account metadata (encrypted)
    json accountsData = json::object();
    if (exists(path(ACCOUNTS_FILE))) {
        try {
            std::ifstream infile(ACCOUNTS_FILE, std::ios::binary);
            std::string encryptedData((std::istreambuf_iterator<char>(infile)),
                                      std::istreambuf_iterator<char>());
            infile.close();
            string decrypted = decryptAccountsData(encryptedData);
            accountsData = json::parse(decrypted);
        } catch (...) {
            accountsData = json::object();
        }
    }
    accountsData[accName] = {
        {"password", accPass},
        {"encryption", type},
        {"id1", id1}
    };

    // Encrypt and save with secure permissions
    string plaintextJson = accountsData.dump(4);
    string encryptedJson = encryptAccountsData(plaintextJson);
    ofstream out(ACCOUNTS_FILE, std::ios::binary);
    out.write(encryptedJson.c_str(), encryptedJson.length());
    out.close();
    setSecureFilePermissions(ACCOUNTS_FILE);

    cout << "Account created with " << type << " encryption (encrypted vault filename)." << endl;
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

    // Remove from account metadata (encrypted)
    if (exists(path(ACCOUNTS_FILE))) {
        try {
            std::ifstream infile(ACCOUNTS_FILE, std::ios::binary);
            std::string encryptedData((std::istreambuf_iterator<char>(infile)),
                                      std::istreambuf_iterator<char>());
            infile.close();
            string decrypted = decryptAccountsData(encryptedData);
            json accountsData = json::parse(decrypted);
            accountsData.erase(accName);

            // Re-encrypt and save
            string plaintextJson = accountsData.dump(4);
            string encryptedJson = encryptAccountsData(plaintextJson);
            ofstream out(ACCOUNTS_FILE, std::ios::binary);
            out.write(encryptedJson.c_str(), encryptedJson.length());
            out.close();
            setSecureFilePermissions(ACCOUNTS_FILE);
        } catch (...) {
            // If decryption fails, just delete the file
            remove(path(ACCOUNTS_FILE));
        }
    }

    // Delete vault file using hashed filename
    string hashedFilename = hashAccountName(accName);
    if (exists(path(hashedFilename))) {
        remove(path(hashedFilename));
    }

    // Also try to delete old-style filename (backward compatibility)
    string oldFilename = accName + ".json";
    if (exists(path(oldFilename))) {
        remove(path(oldFilename));
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

bool PasswordManager::setEncryption(string encryptionType) {
    // Only AES encryption is supported
    string type = "aes";
    // Convert to lowercase
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    saveEncryptionTypeToConfig(type);
    cout << "Encryption type set to: " << type << endl;
    return true;
}

string PasswordManager::getEncryption() const {
    return getEncryptionTypeFromConfig();
}