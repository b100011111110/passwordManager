#include "Manager.h"
#include "MasterKeyManager.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>

using json = nlohmann::json;
using std::filesystem::exists;
using std::filesystem::remove;
using std::filesystem::path;
using std::filesystem::directory_iterator;
using std::ifstream;
using std::ofstream;
using std::string;
using std::cout;
using std::endl;

std::string getDataDirectory() {
    const char* home = getenv("HOME");
    if (!home) {
        throw std::runtime_error("HOME environment variable not set");
    }
    std::string dir = std::string(home) + "/.local/share/passwordManager";
    if (!exists(path(dir))) {
        std::filesystem::create_directories(path(dir));
        chmod(dir.c_str(), S_IRWXU);
    }
    return dir + "/";
}

inline std::string getAccountsFilePath() {
    return getDataDirectory() + "accounts.init";
}

inline std::string getConfigFilePath() {
    return getDataDirectory() + "config.json";
}

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
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if(mdctx) {
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, accountName.c_str(), accountName.length());
        EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash);
        EVP_MD_CTX_free(mdctx);
    }

    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return getDataDirectory() + ss.str() + ".json";
}

string getEncryptionTypeFromConfig() {
    if (exists(path(getConfigFilePath()))) {
        try {
            json config;
            ifstream in(getConfigFilePath());
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
    if (exists(path(getConfigFilePath()))) {
        try {
            ifstream in(getConfigFilePath());
            in >> config;
        } catch (...) {
            config = json::object();
        }
    } else {
        config = json::object();
    }
    config["encryptionType"] = encType;
    ofstream out(getConfigFilePath());
    out << config.dump(4);
}

std::unique_ptr<Encryption> createEncryptionObject(const std::string& type) {
    // Only AES encryption is supported
    return std::make_unique<AESEncryption>();
}

PasswordManager::PasswordManager(std::unique_ptr<Encryption> encryption)
    : encryptionStandard(std::move(encryption)) {
    if (!encryptionStandard) {
        throw std::invalid_argument("Encryption object is null");
    }
    try {
        masterKey = MasterKeyManager::getMasterKey();
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    loadExistingAccounts();
}

void PasswordManager::loadExistingAccounts() {
    if (exists(path(getAccountsFilePath()))) {
        try {
            // Read encrypted data from file
            std::ifstream infile(getAccountsFilePath(), std::ios::binary);
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
    ofstream out(getAccountsFilePath(), std::ios::binary);
    out.write(encryptedJson.c_str(), encryptedJson.length());
    out.close();
    setSecureFilePermissions(getAccountsFilePath());
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
        Account* tempAccount = createLocalAccount(accName, accPass, hashedFilename, encryptionStandard.get());
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
        tempAccount = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard.get());
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
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard.get());
        
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
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard.get());
        
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
        account = createLocalAccount(accName, accPass, meta.hashedFilename, encryptionStandard.get());
        
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