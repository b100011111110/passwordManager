#ifndef MANAGER_H
#define MANAGER_H

#include <iostream>
#include <string>

using std::string;
using std::cout;
using std::endl;

class PasswordManager {
public:
    
    /*
    this is a class that will manage the password manager, 
    it will have methods to 
        create accounts, 
        delete accounts, 
        add passwords, 
        delete passwords,
        passwords
    */

    void createAccount(string accName, string accPass);

    bool deleteAccount(string accName, string accPass);

    void addPassword(string accName, string accPass, string user, string pass);

    bool deletePassword(string accName, string accPass, string user);

    bool viewPasswords(string accName, string accPass,string user);

    ~PasswordManager() = default;

    // We will add the rest of the methods in Stage 2
};

#endif