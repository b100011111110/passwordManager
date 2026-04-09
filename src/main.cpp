#include <iostream>
#include <string>
#include <vector>
#include "Manager.h"
#include "encryption.h"

using std::cout;
using std::endl;
using std::string;
using std::cin;

void printHelp() {
    cout << "Available commands:" << endl;
    cout << "  create [accountName] [accountPassword] - Create a new account" << endl;
    cout << "  delete [accountName] [accountPassword] - Delete an existing account" << endl;
    cout << "  add [accountName] [accountPassword] [username] [password] - Add a password for a user" << endl;
    cout << "  remove [accountName] [accountPassword] [username] - Remove a password for a user" << endl;
    cout << "  view [accountName] [accountPassword] [username] - View password for a user" << endl;
    cout << "  config encryption [aes|rsa|des] - Set encryption type" << endl;
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

    // Load encryption type from config and create appropriate encryption object
    string encType = getEncryptionTypeFromConfig();
    Encryption* encryption = createEncryptionObject(encType);
    PasswordManager mgr(encryption);

    string command = argv[1];
    string acountName = argc > 2 ? argv[2] : "";
    string accountPassword = argc > 3 ? argv[3] : "";

    // check if the command is valid
    if(command != "create" && command != "delete" && command != "add" && command != "remove" && command != "view" && command != "config"){
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

        // Prompt for encryption type
        cout << "Select encryption type:" << endl;
        cout << "1. AES" << endl;
        cout << "2. RSA" << endl;
        cout << "3. DES" << endl;
        cout << "Enter choice (1-3): ";

        string choice;
        std::getline(cin, choice);

        string encType;
        if (choice == "1") {
            encType = "aes";
        } else if (choice == "2") {
            encType = "rsa";
        } else if (choice == "3") {
            encType = "des";
        } else {
            cout << "Invalid choice. Using default AES." << endl;
            encType = "aes";
        }

        if (mgr.createAccount(acountName, accountPassword, encType)) {
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
    else if(command == "config"){
        if (argc < 3 || argv[2] != string("encryption")) {
            cout << "Usage: config encryption [aes|rsa|des]" << endl;
            return 1;
        }
        if (argc != 4) {
            cout << "Usage: config encryption [aes|rsa|des]" << endl;
            return 1;
        }
        string encType = argv[3];
        if (mgr.setEncryption(encType)) {
            cout << "Configuration saved." << endl;
        } else {
            return 1;
        }
    }

    delete encryption;
    return 0;
}