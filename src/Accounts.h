#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <string>
using std::string;

class Account {
    // an abstract class that will represent an account
public:
    virtual string encryptPassword(string pass) = 0;
    virtual string decryptPassword(string pass) = 0;

    virtual bool validateAccountPassword(string pass) = 0;

    virtual bool addPassword(string userPassword,string id,string idPassword)=0;
    virtual bool deletePassword(string userPassword,string id) = 0;  
    virtual bool viewPassword(string userPassword,string id) = 0; 
};

#endif