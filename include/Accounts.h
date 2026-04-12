#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <string>
#include "encryption.h"

class Encryption;

class Account {
    // an abstract class that will represent an account
public:
    virtual std::string encryptPassword(std::string pass) = 0;
    virtual std::string decryptPassword(std::string pass) = 0;

    virtual bool validateAccountPassword(std::string pass) = 0;

    virtual bool addPassword(std::string userPassword, std::string id, std::string idPassword) = 0;
    virtual bool deletePassword(std::string userPassword, std::string id) = 0;
    virtual bool viewPassword(std::string userPassword, std::string id) = 0;

    virtual ~Account() = default;
};

// Factory function to create a LocalAccount
Account* createLocalAccount(std::string user, std::string pass, std::string file, Encryption* type);

#endif