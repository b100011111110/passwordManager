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
  std::map<string, string> vault;

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
    vault[id] = encryptedIdPassword;
    saveVault();
    return true;
  }

  bool deletePassword(string userPassword, string id) override {
    if (!validateAccountPassword(userPassword)) {
      return false;
    }
    if (vault.find(id) != vault.end()) {
      vault.erase(id);
      saveVault();
      return true;
    }
    return false;
  }

  bool viewPassword(string userPassword, string id) override {
    if (!validateAccountPassword(userPassword)) {
      return false;
    }
    if (vault.find(id) != vault.end()) {
      cout << "Password for " << id << ": "
           << decryptPassword(vault[id]) << endl;
      return true;
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
    json vaultData = json::object();
    for (const auto &[id, crypt] : vault) {
      vaultData[id] = crypt;
    }

    string plaintextJson = vaultData.dump();

    string plaintextToEncrypt = "PMGR" + plaintextJson;
    string encryptedData = this->encryptionStandard->encrypt(
        plaintextToEncrypt, this->encryptionKey);

    ofstream out(filePath, std::ios::binary);
    if (!out) {
      throw std::runtime_error("Failed to open vault file for writing");
    }

    out.write(reinterpret_cast<const char *>(vault_salt), 16);
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

    string encryptedData((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    in.close();

    if (encryptedData.empty()) {
      // File only contains salt, vault is empty
      deriveKeyFromPassword(vault_salt);
      vault.clear();
      return;
    }

    deriveKeyFromPassword(vault_salt);

    try {
      string decryptedData =
          this->encryptionStandard->decrypt(encryptedData, this->encryptionKey);

      // Check magic header
      if (decryptedData.size() < 4 || decryptedData.substr(0, 4) != "PMGR") {
        throw std::runtime_error("Wrong account password");
      }

      string plaintextJson = decryptedData.substr(4);
      json vaultData = json::parse(plaintextJson);

      vault.clear();
      
      if (vaultData.is_array()) {
        for (const auto &entry : vaultData) {
          string s = entry.get<string>();
          size_t pos = s.find('|');
          if (pos != string::npos) {
            vault[s.substr(0, pos)] = s.substr(pos + 1);
          }
        }
      } else if (vaultData.is_object()) {
        for (auto& el : vaultData.items()) {
          vault[el.key()] = el.value().get<string>();
        }
      }
    } catch (const std::runtime_error &e) {
      throw;
    } catch (...) {
      throw std::runtime_error("Wrong account password");
    }
  }
};

Account *createLocalAccount(string user, string pass, string file,
                            Encryption *type) {
  return new LocalAccount(user, pass, file, type);
}