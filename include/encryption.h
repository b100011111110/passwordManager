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


#endif // ENCRYPTION_H