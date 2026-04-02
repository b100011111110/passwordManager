#include <iostream>
#include <string>
#include <vector>
#include "Manager.h"

void printHelp() {
    std::cout << "Available commands:" << std::endl;
    std::cout << "  create [accountName] [accountPassword] - Create a new account" << std::endl;
    std::cout << "  delete [accountName] [accountPassword] - Delete an existing account" << std::endl;
    std::cout << "  add [accountName] [accountPassword] [username] [password] - Add a password for a user" << std::endl;
    std::cout << "  remove [accountName] [accountPassword] [username] - Remove a password for a user" << std::endl;
    std::cout << "  view [accountName] [accountPassword] - View all passwords for the account" << std::endl;
}

int main(int argc, char* argv[]) {
    // Basic command-line parsing
    if (argc < 2) {
        printHelp();
        return 1;
    }

    for(int i = 0; i < argc; i++){
        std::cout << "Argument " << i << ": " << argv[i] << std::endl;
    }

    PasswordManager mgr;
    std::string command = argv[1];
    std::string acountName = argv[2];
    std::string accountPassword = argv[3];

    

    // check if the command is valid
    if(command != "create" && command != "delete" && command != "add" && command != "remove" && command != "view"){
        std::cout << "Invalid command: " << command << std::endl;
        printHelp();
        return 1;
    }
    if(command == "help"){
        printHelp();
    }
    else if(command == "create"){
        if (argc != 4) {
            std::cout << "Invalid number of arguments for create command" << std::endl;
            printHelp();
            return 1;
        }
        mgr.createAccount(acountName, accountPassword);
        std::cout << "Account created successfully!" << std::endl;
    }
    else if(command == "delete"){
        if (argc != 4) {
            std::cout << "Invalid number of arguments for create command" << std::endl;
            printHelp();
            return 1;
        }
        bool x = mgr.deleteAccount(acountName, accountPassword);
        if(x){
            std::cout << "Account deleted successfully!" << std::endl;
        }
        else{
            std::cout << "Account deletion failed or Account not found!" << std::endl;
        }
    }
    else if(command == "add"){
        if (argc != 6) {
            std::cout << "Invalid number of arguments for create command" << std::endl;
            printHelp();
            return 1;
        }
        std::string username = argv[4];
        std::string password = argv[5];
        mgr.addPassword(acountName, accountPassword, username, password);
    }
    else if(command == "remove"){
        if (argc != 5) {
            std::cout << "Invalid number of arguments for create command" << std::endl;
            printHelp();
            return 1;
        }
        std::string username = argv[4];
        bool x = mgr.deletePassword(acountName, accountPassword, username);
        if(x){
            std::cout << "Password deleted successfully!" << std::endl;
        }
        else{
            std::cout << "Password deletion failed or Password not found!" << std::endl;
        }
    }
    else if(command == "view"){
        if (argc != 5) {
            std::cout << "Invalid number of arguments for view command" << std::endl;
            printHelp();
            return 1;
        }
        bool x = mgr.viewPasswords(acountName, accountPassword, acountName);
        if(!x){
            std::cout << "Failed to view passwords!" << std::endl;
        }
    }

    return 0;
}