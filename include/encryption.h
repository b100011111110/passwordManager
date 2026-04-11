#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>

using std::string;

class Encryption {
public:
    virtual string encrypt(const string& data, const string& key) = 0;
    virtual string decrypt(const string& data, const string& key) = 0;
    virtual ~Encryption() = default;
};

class AESEncryption : public Encryption {
public:
    string encrypt(const string& data, const string& key) override;
    string decrypt(const string& data, const string& key) override;
    
    // Overloaded methods for vector-based keys (used by vault system)
    string encrypt(const string& data, const std::vector<unsigned char>& rawKey);
    string decrypt(const string& data, const std::vector<unsigned char>& rawKey);
};

#endif // ENCRYPTION_H