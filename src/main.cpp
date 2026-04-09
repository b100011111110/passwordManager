#include <iostream>
#include <string>
#include <vector>
#include "Manager.h"
#include "encryption.h"

using std::cout;
using std::endl;
using std::string;

void printHelp() {
    cout << "Available commands:" << endl;
    cout << "  create [accountName] [accountPassword] - Create a new account" << endl;
    cout << "  delete [accountName] [accountPassword] - Delete an existing account" << endl;
    cout << "  add [accountName] [accountPassword] [username] [password] - Add a password for a user" << endl;
    cout << "  remove [accountName] [accountPassword] [username] - Remove a password for a user" << endl;
    cout << "  view [accountName] [accountPassword] - View all passwords for the account" << endl;
}

int main(int argc, char* argv[]) {
    // Basic command-line parsing
    if (argc < 2) {
        printHelp();
        return 1;
    }

    for(int i = 0; i < argc; i++){
        cout<< "Argument " << i << ": " << argv[i] << endl;
    }

    AESEncryption aes;
    PasswordManager mgr(&aes);

    string command = argv[1];
    string acountName = argv[2];
    string accountPassword = argv[3];



    // check if the command is valid
    if(command != "create" && command != "delete" && command != "add" && command != "remove" && command != "view"){
        cout << "Invalid command: " << command << endl;
        printHelp();
        return 1;
    }
    if(command == "help"){
        printHelp();
    }
    else if(command == "create"){
        if (argc != 4) {
            cout << "Invalid number of arguments for create command" << endl;
            printHelp();
            return 1;
        }
        if (mgr.createAccount(acountName, accountPassword)) {
            cout << "Account created successfully!" << endl;
        }
    }
    else if(command == "delete"){
        if (argc != 4) {
            cout << "Invalid number of arguments for create command" << endl;
            printHelp();
            return 1;
        }
        bool x = mgr.deleteAccount(acountName, accountPassword);
        if(x){
            cout << "Account deleted successfully!" << endl;
        }
        else{
            cout << "Account deletion failed or Account not found!" << endl;
        }
    }
    else if(command == "add"){
        if (argc != 6) {
            cout << "Invalid number of arguments for create command" << endl;
            printHelp();
            return 1;
        }
        string username = argv[4];
        string password = argv[5];
        mgr.addPassword(acountName, accountPassword, username, password);
    }
    else if(command == "remove"){
        if (argc != 5) {
            cout << "Invalid number of arguments for create command" << endl;
            printHelp();
            return 1;
        }
        string username = argv[4];
        bool x = mgr.deletePassword(acountName, accountPassword, username);
        if(x){
            cout << "Password deleted successfully!" << endl;
        }
        else{
            cout << "Password deletion failed or Password not found!" << endl;
        }
    }
    else if(command == "view"){
        if (argc != 5) {
            cout << "Invalid number of arguments for view command" << endl;
            printHelp();
            return 1;
        }
        string username = argv[4];
        bool x = mgr.viewPasswords(acountName, accountPassword, username);
        if(!x){
            cout << "Failed to view passwords!" << endl;
        }
    }

    return 0;
}