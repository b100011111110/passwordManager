#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <string>
#include "encryption.h"

using std::string;

class Encryption;

class Account {
    // an abstract class that will represent an account
public:
    virtual string encryptPassword(string pass) = 0;
    virtual string decryptPassword(string pass) = 0;

    virtual bool validateAccountPassword(string pass) = 0;

    virtual bool addPassword(string userPassword,string id,string idPassword)=0;
    virtual bool deletePassword(string userPassword,string id) = 0;
    virtual bool viewPassword(string userPassword,string id) = 0;

    virtual ~Account() = default;
};

// Factory function to create a LocalAccount
Account* createLocalAccount(string user, string pass, string file, Encryption* type);

#endif