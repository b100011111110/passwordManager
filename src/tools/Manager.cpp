#include "Manager.h"
#include "MasterKeyManager.h"
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

// Set restrictive file permissions (0600 = owner read/write only)
void setSecureFilePermissions(const string& filename) {
    chmod(filename.c_str(), S_IRUSR | S_IWUSR);  // 0600
}

// Encrypt accounts data using AES with hardware-protected master key
string PasswordManager::encryptAccountsData(const string& plaintext) {
    AESEncryption aes;
    return aes.encrypt(plaintext, this->masterKey);  // vector overload — no EVP_BytesToKey
}

// Decrypt accounts data using AES with hardware-protected master key
string PasswordManager::decryptAccountsData(const string& ciphertext) {
    AESEncryption aes;
    return aes.decrypt(ciphertext, this->masterKey);  // vector overload — no EVP_BytesToKey
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
    try {
        masterKey = MasterKeyManager::getMasterKey();
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    loadExistingAccounts();
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
                    string encryption = "aes";  // default

                // Handle both old format (string) and new format (object)
                if (accInfo.is_object()) {
                    if (accInfo.contains("encryption")) {
                        encryption = accInfo["encryption"].get<string>();
                    }
                }

                // Store only metadata, no plaintext passwords
                string hashedFilename = hashAccountName(accName);
                AccountMeta meta = {accName, hashedFilename, encryption};
                accounts[accName] = meta;
            }
        } catch (...) {
            // If loading fails, continue
            cout << "Warning: Could not load existing accounts." << endl;
        }
    }
}

void PasswordManager::saveAccountMetadata() {
    json accountsData = json::object();
    for (const auto& [accName, meta] : accounts) {
        // Store only metadata, no passwords
        accountsData[accName] = {
            {"encryption", meta.encryptionType}
        };
    }
    // Encrypt and save with secure permissions
    string plaintextJson = accountsData.dump(4);
    string encryptedJson = encryptAccountsData(plaintextJson);
    ofstream out(ACCOUNTS_FILE, std::ios::binary);
    out.write(encryptedJson.c_str(), encryptedJson.length());
    out.close();
    setSecureFilePermissions(ACCOUNTS_FILE);
}

PasswordManager::~PasswordManager() {
    // No longer need to delete Account* objects since we store AccountMeta structs
}

bool PasswordManager::createAccount(string accName, string accPass, string encryptionType) {
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
        // Create account object temporarily to validate and create vault file
        Account* tempAccount = createLocalAccount(accName, accPass, hashedFilename, encryptionStandard);
        delete tempAccount;  // Clean up temporary object
        
        // Store only metadata in memory
        AccountMeta meta = {accName, hashedFilename, type};
        accounts[accName] = meta;
        
        // Save account metadata (encrypted, no passwords)
        saveAccountMetadata();
        
    } catch (const std::runtime_error& e) {
        cout << "Failed to create account: " << e.what() << endl;
        return false;
    }

    cout << "Account created with " << type << " encryption (encrypted vault filename)." << endl;
    return true;
}

bool PasswordManager::deleteAccount(string accName, string accPass) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    AccountMeta meta = accounts[accName];
    
    // Create account object temporarily to validate password
    Account* tempAccount = nullptr;
    try {
        tempAccount = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard);
        // If we get here, password is valid
        delete tempAccount;
        tempAccount = nullptr;
    } catch (const std::runtime_error& e) {
        cout << "Invalid account or password." << endl;
        if (tempAccount) delete tempAccount;
        return false;
    }

    // Remove from accounts map
    accounts.erase(accName);

    // Update account metadata file
    saveAccountMetadata();

    // Delete vault file using hashed filename
    if (exists(path(meta.hashedFilename))) {
        remove(path(meta.hashedFilename));
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

    AccountMeta meta = accounts[accName];
    
    // Create account object temporarily to perform operation
    Account* account = nullptr;
    try {
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard);
        
        if (account->addPassword(accPass, user, pass)) {
            cout << "Password added." << endl;
        } else {
            cout << "Failed to add password." << endl;
        }
        
        delete account;
    } catch (const std::runtime_error& e) {
        cout << "Invalid account or password." << endl;
        if (account) delete account;
    }
}

bool PasswordManager::deletePassword(string accName, string accPass, string user) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    AccountMeta meta = accounts[accName];
    
    // Create account object temporarily to perform operation
    Account* account = nullptr;
    try {
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard);
        
        if (account->deletePassword(accPass, user)) {
            cout << "Password deleted." << endl;
            delete account;
            return true;
        } else {
            cout << "Password not found." << endl;
            delete account;
            return false;
        }
    } catch (const std::runtime_error& e) {
        cout << "Invalid account or password." << endl;
        if (account) delete account;
        return false;
    }
}

bool PasswordManager::viewPasswords(string accName, string accPass, string user) {
    if (accounts.find(accName) == accounts.end()) {
        cout << "Invalid account or password." << endl;
        return false;
    }

    AccountMeta meta = accounts[accName];
    
    // Create account object temporarily to perform operation
    Account* account = nullptr;
    try {
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard);
        
        if (user.empty()) {
            cout << "Viewing all passwords - feature not fully implemented" << endl;
            delete account;
            return false;
        }

        bool result = account->viewPassword(accPass, user);
        delete account;
        return result;
    } catch (const std::runtime_error& e) {
        cout << "Invalid account or password." << endl;
        if (account) delete account;
        return false;
    }
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