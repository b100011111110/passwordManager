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
#include <pwd.h>
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
        throw std::runtime_error(string("Failed retrieve: ") + e.what());
    }

    throw std::runtime_error("Master key unavailable. Your data cannot be accessed.");
}

bool MasterKeyManager::sealToTPM(const vector<unsigned char>& key) {
    char primaryCtxPath[] = "/tmp/pm_primary.ctx_XXXXXX";
    int fd = mkstemp(primaryCtxPath);
    if (fd == -1) return false;
    close(fd);

    try {
        string hexKey = toHex(key);
        string pubPath = getTpmKeyPath() + ".pub";
        string privPath = getTpmKeyPath() + ".priv";

        // Create primary key
        string cmd1 = "tpm2_createprimary -C o -G rsa -g sha256 -c " + string(primaryCtxPath) + " 2>/dev/null";
        if (system(cmd1.c_str()) != 0) {
            remove(primaryCtxPath);
            return false;
        }

        // Create sealed object reading from stdin
        string cmd2 = "tpm2_create -C " + string(primaryCtxPath) + " -L \"pcr:sha256:0,1,2,7\" -u \"" + pubPath + "\" -r \"" + privPath + "\" -i- 2>/dev/null";
        FILE* pipe = popen(cmd2.c_str(), "w");
        if (!pipe) {
            remove(primaryCtxPath);
            return false;
        }
        
        fwrite(hexKey.data(), 1, hexKey.size(), pipe);
        int result = pclose(pipe);

        // Clean up
        remove(primaryCtxPath);

        return result == 0;
    } catch (...) {
        remove(primaryCtxPath);
        return false;
    }
}

std::vector<unsigned char> MasterKeyManager::unsealFromTPM() {
    char primaryCtxPath[] = "/tmp/pm_primary.ctx_XXXXXX";
    int fd1 = mkstemp(primaryCtxPath);
    if (fd1 == -1) throw std::runtime_error("Failed to create temp file");
    close(fd1);

    char loadedCtxPath[] = "/tmp/pm_loaded.ctx_XXXXXX";
    int fd2 = mkstemp(loadedCtxPath);
    if (fd2 == -1) {
        remove(primaryCtxPath);
        throw std::runtime_error("Failed to create temp file");
    }
    close(fd2);

    try {
        string pubPath = getTpmKeyPath() + ".pub";
        string privPath = getTpmKeyPath() + ".priv";

        // Check if TPM files exist
        if (!exists(path(pubPath)) || !exists(path(privPath))) {
            throw std::runtime_error("TPM key files not found");
        }

        // Create primary key
        string cmd1 = "tpm2_createprimary -C o -G rsa -g sha256 -c " + string(primaryCtxPath) + " 2>/dev/null";
        if (system(cmd1.c_str()) != 0) {
            throw std::runtime_error("TPM primary key creation failed");
        }

        // Load the sealed object
        string cmd2 = "tpm2_load -C " + string(primaryCtxPath) + " -u \"" + pubPath + "\" -r \"" + privPath + "\" -c " + string(loadedCtxPath) + " 2>/dev/null";
        if (system(cmd2.c_str()) != 0) {
            throw std::runtime_error("TPM load failed");
        }

        // Unseal
        string cmd3 = "tpm2_unseal -c " + string(loadedCtxPath) + " -p pcr:sha256:0,1,2,7 2>/dev/null";
        FILE* pipe = popen(cmd3.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("TPM unseal pipe failed");
        }

        char buffer[128];
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
        remove(primaryCtxPath);
        remove(loadedCtxPath);

        if (output.empty()) {
            throw std::runtime_error("TPM unseal returned empty");
        }

        return fromHex(output);
    } catch (...) {
        remove(primaryCtxPath);
        remove(loadedCtxPath);
        throw;
    }
}

bool MasterKeyManager::storeInLibsecret(const vector<unsigned char>& key) {
    try {
        string hexKey = toHex(key);
        string cmd = "secret-tool store --label='passwordManager master key' application passwordManager key master 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "w");
        if (!pipe) {
            return false;
        }
        fputs(hexKey.c_str(), pipe);
        fputs("\n", pipe);
        int status = pclose(pipe);
        return status == 0;
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
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            machineKey += hostname;
        }
        
        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_name) {
            machineKey += pw->pw_name;
        }
        
        if (machineKey.empty()) machineKey = "default";

        // Generate 16 byte salt
        unsigned char salt[16];
        if (!RAND_bytes(salt, sizeof(salt))) {
            return false;
        }

        // Derive encryption key from machine-specific string using PBKDF2
        vector<unsigned char> fileKey(32);
        if (PKCS5_PBKDF2_HMAC(machineKey.c_str(), machineKey.size(),
                              salt, sizeof(salt), 200000,
                              EVP_sha256(), 32, fileKey.data()) != 1) {
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

        keyFile.write(reinterpret_cast<const char*>(salt), sizeof(salt));
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
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            machineKey += hostname;
        }
        
        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_name) {
            machineKey += pw->pw_name;
        }
        
        if (machineKey.empty()) machineKey = "default";

        // Read encrypted key from file
        string keyFilePath = getMetaPath();
        keyFilePath = keyFilePath.substr(0, keyFilePath.find_last_of('/')) + "/master.key";

        std::ifstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Master key file not found");
        }

        unsigned char salt[16];
        keyFile.read(reinterpret_cast<char*>(salt), sizeof(salt));
        if (keyFile.gcount() != sizeof(salt)) {
            throw std::runtime_error("Invalid master key file format");
        }

        string encrypted((std::istreambuf_iterator<char>(keyFile)),
                        std::istreambuf_iterator<char>());
        keyFile.close();

        // Derive encryption key from machine-specific string using PBKDF2
        vector<unsigned char> fileKey(32);
        if (PKCS5_PBKDF2_HMAC(machineKey.c_str(), machineKey.size(),
                              salt, sizeof(salt), 200000,
                              EVP_sha256(), 32, fileKey.data()) != 1) {
            throw std::runtime_error("Failed to derive file encryption key");
        }

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