#include "Manager.h"
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::ifstream;
using std::ofstream;
using std::filesystem::exists;
using std::filesystem::remove;
using std::filesystem::path;

const string DATA_FILE = "data.init";

void PasswordManager::createAccount(string accName, string accPass) {
    json data;
    if (exists(path(DATA_FILE))) {
        ifstream in(DATA_FILE);
        in >> data;
    } else {
        data = json::object();
    }
    if (data.contains(accName)) {
        cout << "Account already exists." << endl;
        return;
    }
    data[accName] = accPass;
    ofstream out(DATA_FILE);
    out << data.dump(4);
    // Create individual file
    string filename = accName + ".json";
    json accData = json::object();
    ofstream accOut(filename);
    accOut << accData.dump(4);
    cout << "Account created." << endl;
}

bool PasswordManager::deleteAccount(string accName, string accPass) {
    json data;
    if (!exists(path(DATA_FILE))) {
        cout << "No accounts file." << endl;
        return false;
    }
    ifstream in(DATA_FILE);
    in >> data;
    if (!data.contains(accName) || data[accName] != accPass) {
        cout << "Invalid account or password." << endl;
        return false;
    }
    data.erase(accName);
    ofstream out(DATA_FILE);
    out << data.dump(4);
    // Delete individual file
    string filename = accName + ".json";
    if (exists(path(filename))) {
        remove(path(filename));
    }
    cout << "Account deleted." << endl;
    return true;
}

void PasswordManager::addPassword(string accName, string accPass, string user, string pass) {
    json data;
    if (!exists(path(DATA_FILE))) {
        cout << "No accounts file." << endl;
        return;
    }
    ifstream in(DATA_FILE);
    in >> data;
    if (!data.contains(accName) || data[accName] != accPass) {
        cout << "Invalid account or password." << endl;
        return;
    }
    string filename = accName + ".json";
    json accData;
    if (exists(path(filename))) {
        ifstream accIn(filename);
        accIn >> accData;
    } else {
        accData = json::object();
    }
    accData[user] = pass;
    ofstream accOut(filename);
    accOut << accData.dump(4);
    cout << "Password added." << endl;
}

bool PasswordManager::deletePassword(string accName, string accPass, string user) {
    json data;
    if (!exists(path(DATA_FILE))) {
        cout << "No accounts file." << endl;
        return false;
    }
    ifstream in(DATA_FILE);
    in >> data;
    if (!data.contains(accName) || data[accName] != accPass) {
        cout << "Invalid account or password." << endl;
        return false;
    }
    string filename = accName + ".json";
    if (!exists(path(filename))) {
        cout << "Account file not found." << endl;
        return false;
    }
    json accData;
    ifstream accIn(filename);
    accIn >> accData;
    if (!accData.contains(user)) {
        cout << "User not found." << endl;
        return false;
    }
    accData.erase(user);
    ofstream accOut(filename);
    accOut << accData.dump(4);
    cout << "Password deleted." << endl;
    return true;
}

bool PasswordManager::viewPasswords(string accName, string accPass, string user) {
    json data;
    if (!exists(path(DATA_FILE))) {
        cout << "No accounts file." << endl;
        return false;
    }
    ifstream in(DATA_FILE);
    in >> data;
    if (!data.contains(accName) || data[accName] != accPass) {
        cout << "Invalid account or password." << endl;
        return false;
    }
    string filename = accName + ".json";
    if (!exists(path(filename))) {
        cout << "Account file not found." << endl;
        return false;
    }
    json accData;
    ifstream accIn(filename);
    accIn >> accData;
    if (user.empty()) {
        // View all
        cout << "Passwords:" << endl;
        for (auto& item : accData.items()) {
            cout << item.key() << ": " << item.value() << endl;
        }
    } else {
        if (!accData.contains(user)) {
            cout << "User not found." << endl;
            return false;
        }
        cout << "Password for " << user << ": " << accData[user] << endl;
    }
    return true;
}