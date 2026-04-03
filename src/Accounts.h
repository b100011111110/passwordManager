#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <string>
using std::string;


class Account {
    // an abstract class that will represent an account
public:
    virtual void encryptPassword(string pass) = 0;
    virtual void decryptPassword(string pass) = 0;

    virtual void saveToFile() = 0;
    virtual void loadFromFile() = 0;

    virtual bool validatePassword(string pass) = 0;

    virtual void addPassword(string user, string pass) = 0;
    virtual void deletePassword(string user) = 0;
    virtual void viewPassword(string user) = 0;
};

#endif