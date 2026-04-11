#include "MasterKeyManager.h"
#include "encryption.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

using std::string;
using std::vector;
using std::filesystem::path;
using std::filesystem::exists;
using std::filesystem::create_directories;

bool MasterKeyManager::isFirstRun() {
    return !exists(path(getMetaPath()));
}

std::vector<unsigned char> MasterKeyManager::getMasterKey() {
    if (isFirstRun()) {
        return generateAndStoreMasterKey();
    } else {
        return retrieveMasterKey();
    }
}

std::vector<unsigned char> MasterKeyManager::generateAndStoreMasterKey() {
    // Create directory ~/.config/passwordManager/ with permissions 0700
    string configDir = string(getenv("HOME") ? getenv("HOME") : "") + "/.config/passwordManager";
    create_directories(path(configDir));
    chmod(configDir.c_str(), S_IRWXU);  // 0700

    // Generate 32 random bytes
    vector<unsigned char> key(32);
    if (!RAND_bytes(key.data(), key.size())) {
        throw std::runtime_error("Failed to generate random master key");
    }

    // Try to seal to TPM
    bool tpmSuccess = sealToTPM(key);
    if (!tpmSuccess) {
        std::cerr << "Warning: TPM sealing failed, continuing..." << std::endl;
    }

    // Try libsecret fallback
    bool libsecretSuccess = storeInLibsecret(key);
    if (!libsecretSuccess) {
        std::cerr << "Warning: libsecret storage failed, continuing..." << std::endl;
    }

    // Development fallback: store encrypted in file using machine-specific key
    bool fileSuccess = storeInEncryptedFile(key);
    if (!fileSuccess) {
        std::cerr << "Warning: encrypted file storage failed, continuing..." << std::endl;
    }

    // If all backends failed, throw error
    if (!tpmSuccess && !libsecretSuccess && !fileSuccess) {
        throw std::runtime_error("Failed to store master key in any backend");
    }

    // Write meta file
    std::ofstream metaFile(getMetaPath());
    metaFile << "initialized";
    metaFile.close();
    chmod(getMetaPath().c_str(), S_IRUSR | S_IWUSR);  // 0600

    return key;
}

std::vector<unsigned char> MasterKeyManager::retrieveMasterKey() {
    // Try TPM first
    try {
        vector<unsigned char> key = unsealFromTPM();
        if (key.size() == 32) {
            return key;
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "TPM unavailable, falling back to keyring..." << std::endl;
    }

    // Try libsecret fallback
    try {
        vector<unsigned char> key = retrieveFromLibsecret();
        if (key.size() == 32) {
            return key;
        }
    } catch (const std::runtime_error& e) {
        // Continue to file fallback
    }

    // Development fallback: try encrypted file
    try {
        vector<unsigned char> key = retrieveFromEncryptedFile();
        if (key.size() == 32) {
            return key;
        }
    } catch (const std::runtime_error& e) {
        // Continue to error
    }

    throw std::runtime_error("Master key unavailable. Your data cannot be accessed.");
}

bool MasterKeyManager::sealToTPM(const vector<unsigned char>& key) {
    try {
        string hexKey = toHex(key);
        string pubPath = getTpmKeyPath() + ".pub";
        string privPath = getTpmKeyPath() + ".priv";

        // Create primary key
        string cmd1 = "tpm2_createprimary -C o -G rsa -g sha256 -c /tmp/pm_primary.ctx 2>/dev/null";
        if (system(cmd1.c_str()) != 0) {
            return false;
        }

        // Create sealed object
        string cmd2 = "echo '" + hexKey + "' | tpm2_create -C /tmp/pm_primary.ctx -L 'pcr:sha256:0,1,2,7' -i - -u '" + pubPath + "' -r '" + privPath + "' 2>/dev/null";
        int result = system(cmd2.c_str());

        // Clean up
        remove("/tmp/pm_primary.ctx");

        return result == 0;
    } catch (...) {
        return false;
    }
}

std::vector<unsigned char> MasterKeyManager::unsealFromTPM() {
    try {
        string pubPath = getTpmKeyPath() + ".pub";
        string privPath = getTpmKeyPath() + ".priv";

        // Check if TPM files exist
        if (!exists(path(pubPath)) || !exists(path(privPath))) {
            throw std::runtime_error("TPM key files not found");
        }

        // Create primary key
        string cmd1 = "tpm2_createprimary -C o -G rsa -g sha256 -c /tmp/pm_primary.ctx 2>/dev/null";
        if (system(cmd1.c_str()) != 0) {
            throw std::runtime_error("TPM primary key creation failed");
        }

        // Load the sealed object
        string cmd2 = "tpm2_load -C /tmp/pm_primary.ctx -u '" + pubPath + "' -r '" + privPath + "' -c /tmp/pm_loaded.ctx 2>/dev/null";
        if (system(cmd2.c_str()) != 0) {
            remove("/tmp/pm_primary.ctx");
            throw std::runtime_error("TPM load failed");
        }

        // Unseal
        string cmd3 = "tpm2_unseal -c /tmp/pm_loaded.ctx -p pcr:sha256:0,1,2,7 2>/dev/null";
        FILE* pipe = popen(cmd3.c_str(), "r");
        if (!pipe) {
            remove("/tmp/pm_primary.ctx");
            remove("/tmp/pm_loaded.ctx");
            throw std::runtime_error("TPM unseal pipe failed");
        }

        char buffer[65];  // 32 bytes * 2 + newline
        string output;
        if (fgets(buffer, sizeof(buffer), pipe)) {
            output = buffer;
            // Remove trailing newline
            if (!output.empty() && output.back() == '\n') {
                output.pop_back();
            }
        }
        pclose(pipe);

        // Clean up
        remove("/tmp/pm_primary.ctx");
        remove("/tmp/pm_loaded.ctx");

        if (output.empty()) {
            throw std::runtime_error("TPM unseal returned empty");
        }

        return fromHex(output);
    } catch (const std::runtime_error& e) {
        throw;
    } catch (...) {
        throw std::runtime_error("TPM unseal failed");
    }
}

bool MasterKeyManager::storeInLibsecret(const vector<unsigned char>& key) {
    try {
        string hexKey = toHex(key);
        string cmd = "echo '" + hexKey + "' | secret-tool store --label='passwordManager master key' application passwordManager key master 2>/dev/null";
        return system(cmd.c_str()) == 0;
    } catch (...) {
        return false;
    }
}

std::vector<unsigned char> MasterKeyManager::retrieveFromLibsecret() {
    try {
        string cmd = "secret-tool lookup application passwordManager key master 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("libsecret lookup pipe failed");
        }

        char buffer[65];
        string output;
        if (fgets(buffer, sizeof(buffer), pipe)) {
            output = buffer;
            if (!output.empty() && output.back() == '\n') {
                output.pop_back();
            }
        }
        pclose(pipe);

        if (output.empty()) {
            throw std::runtime_error("libsecret lookup returned empty");
        }

        return fromHex(output);
    } catch (const std::runtime_error& e) {
        throw;
    } catch (...) {
        throw std::runtime_error("libsecret retrieval failed");
    }
}

bool MasterKeyManager::storeInEncryptedFile(const vector<unsigned char>& key) {
    try {
        // Generate machine-specific key from hostname + username
        string machineKey = "";
        const char* hostname = getenv("HOSTNAME");
        const char* user = getenv("USER");
        if (hostname) machineKey += hostname;
        if (user) machineKey += user;
        if (machineKey.empty()) machineKey = "default";

        // Derive encryption key from machine-specific string
        vector<unsigned char> fileKey(32);
        if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                           reinterpret_cast<const unsigned char*>(machineKey.data()),
                           static_cast<int>(machineKey.size()), 10000,  // 10,000 iterations
                           fileKey.data(), nullptr)) {
            return false;
        }

        // Encrypt the master key
        AESEncryption aes;
        string hexKey = toHex(key);
        string encrypted = aes.encrypt(hexKey, fileKey);

        // Store in file
        string keyFilePath = getMetaPath();
        keyFilePath = keyFilePath.substr(0, keyFilePath.find_last_of('/')) + "/master.key";

        std::ofstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile) return false;

        keyFile.write(encrypted.data(), encrypted.size());
        keyFile.close();

        // Set restrictive permissions
        chmod(keyFilePath.c_str(), S_IRUSR | S_IWUSR);

        return true;
    } catch (...) {
        return false;
    }
}

std::vector<unsigned char> MasterKeyManager::retrieveFromEncryptedFile() {
    try {
        // Generate machine-specific key from hostname + username
        string machineKey = "";
        const char* hostname = getenv("HOSTNAME");
        const char* user = getenv("USER");
        if (hostname) machineKey += hostname;
        if (user) machineKey += user;
        if (machineKey.empty()) machineKey = "default";

        // Derive encryption key from machine-specific string
        vector<unsigned char> fileKey(32);
        if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                           reinterpret_cast<const unsigned char*>(machineKey.data()),
                           static_cast<int>(machineKey.size()), 10000,  // 10,000 iterations
                           fileKey.data(), nullptr)) {
            throw std::runtime_error("Failed to derive file encryption key");
        }

        // Read encrypted key from file
        string keyFilePath = getMetaPath();
        keyFilePath = keyFilePath.substr(0, keyFilePath.find_last_of('/')) + "/master.key";

        std::ifstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Master key file not found");
        }

        string encrypted((std::istreambuf_iterator<char>(keyFile)),
                        std::istreambuf_iterator<char>());
        keyFile.close();

        // Decrypt the master key
        AESEncryption aes;
        string decryptedHex = aes.decrypt(encrypted, fileKey);

        return fromHex(decryptedHex);
    } catch (const std::runtime_error& e) {
        throw;
    } catch (...) {
        throw std::runtime_error("Failed to retrieve master key from encrypted file");
    }
}

std::string MasterKeyManager::toHex(const vector<unsigned char>& data) {
    static const char* hexChars = "0123456789abcdef";
    string result;
    result.reserve(data.size() * 2);
    for (unsigned char c : data) {
        result.push_back(hexChars[c >> 4]);
        result.push_back(hexChars[c & 0x0F]);
    }
    return result;
}

std::vector<unsigned char> MasterKeyManager::fromHex(const string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }
    vector<unsigned char> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        result.push_back(static_cast<unsigned char>(byte));
    }
    return result;
}

std::string MasterKeyManager::getMetaPath() {
    const char* home = getenv("HOME");
    if (!home) {
        throw std::runtime_error("HOME environment variable not set");
    }
    return string(home) + "/.config/passwordManager/tpm.meta";
}

std::string MasterKeyManager::getTpmKeyPath() {
    const char* home = getenv("HOME");
    if (!home) {
        throw std::runtime_error("HOME environment variable not set");
    }
    return string(home) + "/.config/passwordManager/tpm";
}