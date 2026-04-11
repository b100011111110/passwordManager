#ifndef MASTERKEYMANAGER_H
#define MASTERKEYMANAGER_H

#include <vector>
#include <string>

class MasterKeyManager {
public:
    // Returns 32-byte master key. Throws std::runtime_error if unavailable.
    static std::vector<unsigned char> getMasterKey();

private:
    static bool isFirstRun();
    static std::vector<unsigned char> generateAndStoreMasterKey();
    static std::vector<unsigned char> retrieveMasterKey();

    // TPM operations via tpm2-tools CLI
    static bool sealToTPM(const std::vector<unsigned char>& key);
    static std::vector<unsigned char> unsealFromTPM();

    // libsecret fallback via CLI
    static bool storeInLibsecret(const std::vector<unsigned char>& key);
    static std::vector<unsigned char> retrieveFromLibsecret();

    // Helpers
    static std::string toHex(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> fromHex(const std::string& hex);
    static std::string getMetaPath();   // ~/.config/passwordManager/tpm.meta
    static std::string getTpmKeyPath(); // ~/.config/passwordManager/tpm.key
};

#endif