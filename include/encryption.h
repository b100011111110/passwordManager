#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

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
};

class RSAEncryption : public Encryption {
public:
    string encrypt(const string& data, const string& key) override;
    string decrypt(const string& data, const string& key) override;
};

class DESEncryption : public Encryption {
public:
    string encrypt(const string& data, const string& key) override;
    string decrypt(const string& data, const string& key) override;
};

#endif // ENCRYPTION_H