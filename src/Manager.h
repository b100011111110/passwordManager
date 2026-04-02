#ifndef MANAGER_H
#define MANAGER_H

#include <iostream>
#include <string>

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

    void createAccount(std::string accName, std::string accPass) {
        std::cout << "Creating account: " << accName << " with password: " << accPass << std::endl;
    }

    bool deleteAccount(std::string accName, std::string accPass) {
        std::cout << "Deleting account: " << accName << std::endl;
        return true; 
    }

    void addPassword(std::string accName, std::string accPass, std::string user, std::string pass) {
        std::cout << "Adding password for user: " << user << std::endl;
        return;
    }

    bool deletePassword(std::string accName, std::string accPass, std::string user) {
        std::cout << "Deleting password for user: " << user << std::endl;
        return true;
    }

    bool viewPasswords(std::string accName, std::string accPass,std::string user) {
        std::cout << "Viewing passwords for user: " << user << std::endl;
        return true;
    }

    // We will add the rest of the methods in Stage 2
};

#endif