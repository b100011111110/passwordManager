#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <termios.h>
#include <unistd.h>
#include "Manager.h"
#include "encryption.h"

using std::cout;
using std::endl;
using std::string;
using std::cin;

// Function to read password with hidden input (asterisks shown in real-time)
string readPasswordHidden() {
    string password;
    char ch;

    // Flush output buffer to ensure prompt is displayed
    cout.flush();
    fflush(stdout);

    // Get current terminal settings
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // Disable echo and set non-canonical mode
    newt.c_lflag &= ~(ECHO | ICANON);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Read password character by character
    while (read(STDIN_FILENO, &ch, 1) == 1) {
        if (ch == '\n') {
            break;
        }
        if (ch == '\b' || ch == 127) {  // Backspace or DEL
            if (!password.empty()) {
                password.pop_back();
                cout << "\b \b";
                cout.flush();
            }
        } else {
            password += ch;
            cout << "*";
            cout.flush();
        }
    }

    cout << endl;

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return password;
}

void printHelp() {
    cout << "Available commands:" << endl;
    cout << "  create [accountName] - Create a new account (password will be prompted)" << endl;
    cout << "  delete [accountName] - Delete an existing account (password will be prompted)" << endl;
    cout << "  add [accountName] [username] - Add a password for a user (passwords will be prompted)" << endl;
    cout << "  remove [accountName] [username] - Remove a password for a user (account password will be prompted)" << endl;
    cout << "  view [accountName] [username] - View password for a user (account password will be prompted)" << endl;
    cout << "  config encryption [aes|rsa|des] - Set encryption type" << endl;
}

int main(int argc, char* argv[]) {
    // Basic command-line parsing
    if (argc < 2) {
        printHelp();
        return 1;
    }

    // Load encryption type from config and create appropriate encryption object
    string encType = getEncryptionTypeFromConfig();
    Encryption* encryption = createEncryptionObject(encType);
    {
        PasswordManager mgr(encryption);

        string command = argv[1];
        string acountName = argc > 2 ? argv[2] : "";
        string accountPassword = argc > 3 ? argv[3] : "";

        // check if the command is valid
        if(command != "create" && command != "delete" && command != "add" && command != "remove" && command != "view" && command != "config"){
            cout << "Invalid command: " << command << endl;
            printHelp();
            delete encryption;
            return 1;
        }
        if(command == "help"){
            printHelp();
        }
        else if(command == "create"){
            if (argc != 3) {
                cout << "Usage: passwordManager create [accountName]" << endl;
                delete encryption;
                return 1;
            }

            // Prompt for password
            cout << "Enter account password: ";
            accountPassword = readPasswordHidden();

            // Prompt for encryption type
            cout << "Select encryption type:" << endl;
            cout << "1. AES" << endl;
            cout << "2. RSA" << endl;
            cout << "3. DES" << endl;
            cout << "Enter choice (1-3): ";

            string choice;
            std::getline(std::cin, choice);

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
            if (argc != 3) {
                cout << "Usage: passwordManager delete [accountName]" << endl;
                delete encryption;
                return 1;
            }

            // Prompt for password
            cout << "Enter account password: ";
            accountPassword = readPasswordHidden();

            bool x = mgr.deleteAccount(acountName, accountPassword);
            if(x){
                cout << "Account deleted successfully!" << endl;
            }
            else{
                cout << "Account deletion failed or Account not found!" << endl;
            }
        }
        else if(command == "add"){
            if (argc != 4) {
                cout << "Usage: passwordManager add [accountName] [username]" << endl;
                delete encryption;
                return 1;
            }

            string username = argv[3];

            // Prompt for account password
            cout << "Enter account password: ";
            accountPassword = readPasswordHidden();

            // Prompt for user password
            cout << "Enter password for user '" << username << "': ";
            string password = readPasswordHidden();

            mgr.addPassword(acountName, accountPassword, username, password);
        }
        else if(command == "remove"){
            if (argc != 4) {
                cout << "Usage: passwordManager remove [accountName] [username]" << endl;
                delete encryption;
                return 1;
            }
            string username = argv[3];

            // Prompt for account password
            cout << "Enter account password: ";
            accountPassword = readPasswordHidden();

            bool x = mgr.deletePassword(acountName, accountPassword, username);
            if(x){
                cout << "Password deleted successfully!" << endl;
            }
            else{
                cout << "Password deletion failed or Password not found!" << endl;
            }
        }
        else if(command == "view"){
            if (argc != 4) {
                cout << "Usage: passwordManager view [accountName] [username]" << endl;
                delete encryption;
                return 1;
            }
            string username = argv[3];

            // Prompt for account password
            cout << "Enter account password: ";
            accountPassword = readPasswordHidden();

            bool x = mgr.viewPasswords(acountName, accountPassword, username);
            if(!x){
                cout << "Failed to view passwords!" << endl;
            }
        }
    }  // mgr goes out of scope and is destroyed here
    delete encryption;
    return 0;
}