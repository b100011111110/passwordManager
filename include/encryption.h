#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>

class Encryption {
public:
    virtual std::string encrypt(const std::string& data, const std::vector<unsigned char>& key) = 0;
    virtual std::string decrypt(const std::string& data, const std::vector<unsigned char>& key) = 0;
    virtual ~Encryption() = default;
};

class AESEncryption : public Encryption {
public:
    std::string encrypt(const std::string& data, const std::vector<unsigned char>& key) override;
    std::string decrypt(const std::string& data, const std::vector<unsigned char>& key) override;
};

#endif 