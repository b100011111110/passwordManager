#include "Accounts.h"
#include "encryption.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>
#include <sys/stat.h>

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::string;
using std::vector;

class LocalAccount : public Account {
  /*
      this is a class that is an implementation of the Account class
      it will represent a local account that will store the passwords in a file
  */

  string password;
  string filePath;
  std::vector<unsigned char> encryptionKey; // 32-byte derived key
  unsigned char vault_salt[16] = {};        // 16-byte salt from vault file
  Encryption *encryptionStandard;
  vector<string> vault;

public:
  string username;

  LocalAccount(string user, string pass, string file, Encryption *type)
      : username(user), password(pass), filePath(file),
        encryptionStandard(type) {
    // Load vault and derive key from vault salt
    loadVault();
  }

  virtual ~LocalAccount() = default;

  bool validateAccountPassword(std::string pass) override {
    return pass == this->password;
  }

  std::string encryptPassword(std::string pass) override {
    if (this->encryptionStandard == nullptr) {
      throw std::runtime_error("Encryption standard is null");
    }
    return this->encryptionStandard->encrypt(pass, this->encryptionKey);
  }

  std::string decryptPassword(std::string pass) override {
    if (this->encryptionStandard == nullptr) {
      throw std::runtime_error("Encryption standard is null");
    }
    return this->encryptionStandard->decrypt(pass, this->encryptionKey);
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
    for (const auto &entry : vault) {
      if (entry.substr(0, entry.find('|')) == id) {
        string encryptedPassword = entry.substr(entry.find('|') + 1);
        cout << "Password for " << id << ": "
             << decryptPassword(encryptedPassword) << endl;
        return true;
      }
    }
    return false;
  }

private:
  void deriveKeyFromPassword(const unsigned char *salt) {
    // PBKDF2: 200,000 iterations, SHA256, 32-byte output
    unsigned char derived[32];

    int ret = PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 16,
                                200000, EVP_sha256(), 32, derived);

    if (ret != 1) {
      throw std::runtime_error("PBKDF2 derivation failed");
    }

    encryptionKey = std::vector<unsigned char>(derived, derived + 32);
  }

  void saveVault() {
    // Create JSON array of entries
    json vaultData = json::array();
    for (const auto &entry : vault) {
      vaultData.push_back(entry);
    }

    // Serialize to string
    string plaintextJson = vaultData.dump();

    // Prepend magic header "PMGR"
    string plaintextToEncrypt = "PMGR" + plaintextJson;

    string encryptedData = this->encryptionStandard->encrypt(
        plaintextToEncrypt, this->encryptionKey);

    // Write vault file: [16 bytes salt] + [encrypted blob]
    ofstream out(filePath, std::ios::binary);
    if (!out) {
      throw std::runtime_error("Failed to open vault file for writing");
    }

    // Write salt
    out.write(reinterpret_cast<const char *>(vault_salt), 16);

    // Write encrypted data
    out.write(encryptedData.c_str(), encryptedData.length());
    out.close();

    // Secure the file preventing public observation access (0600)
    chmod(filePath.c_str(), S_IRUSR | S_IWUSR);
  }

  void loadVault() {
    ifstream in(filePath, std::ios::binary);
    if (!in) {
      // File doesn't exist yet - generate new salt for first save
      if (!RAND_bytes(vault_salt, sizeof(vault_salt))) {
        throw std::runtime_error("RAND_bytes failed for salt generation");
      }
      deriveKeyFromPassword(vault_salt);
      vault.clear();
      saveVault();
      return;
    }

    // Read salt from first 16 bytes
    in.read(reinterpret_cast<char *>(vault_salt), 16);
    if (in.gcount() != 16) {
      in.close();
      throw std::runtime_error("Vault file too short, cannot read salt");
    }

    // Read encrypted data (remaining bytes)
    string encryptedData((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    in.close();

    if (encryptedData.empty()) {
      // File only contains salt, vault is empty
      deriveKeyFromPassword(vault_salt);
      vault.clear();
      return;
    }

    // Derive key using salt from file
    deriveKeyFromPassword(vault_salt);

    try {
      // Decrypt
      string decryptedData =
          this->encryptionStandard->decrypt(encryptedData, this->encryptionKey);

      // Check magic header
      if (decryptedData.size() < 4 || decryptedData.substr(0, 4) != "PMGR") {
        throw std::runtime_error("Wrong account password");
      }

      // Extract plaintext JSON
      string plaintextJson = decryptedData.substr(4);

      // Parse JSON
      json vaultData = json::parse(plaintextJson);

      vault.clear();
      for (const auto &entry : vaultData) {
        vault.push_back(entry.get<string>());
      }
    } catch (const std::runtime_error &e) {
      // Re-throw password errors
      throw;
    } catch (...) {
      throw std::runtime_error("Wrong account password");
    }
  }
};

// Factory function to create a LocalAccount
Account *createLocalAccount(string user, string pass, string file,
                            Encryption *type) {
  return new LocalAccount(user, pass, file, type);
}