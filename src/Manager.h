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

    void createAccount(string accName, string accPass) {
        cout << "Creating account: " << accName << " with password: " << accPass << endl;
    }

    bool deleteAccount(string accName, string accPass) {
        cout << "Deleting account: " << accName << endl;
        return true; 
    }

    void addPassword(string accName, string accPass, string user, string pass) {
        cout << "Adding password for user: " << user << endl;
        return;
    }

    bool deletePassword(string accName, string accPass, string user) {
        cout << "Deleting password for user: " << user << endl;
        return true;
    }

    bool viewPasswords(string accName, string accPass,string user) {
        cout << "Viewing passwords for user: " << user << endl;
        return true;
    }

    // We will add the rest of the methods in Stage 2
};

#endif