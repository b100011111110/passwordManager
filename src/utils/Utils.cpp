#include "utils.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <random>
#include <sstream>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>

using std::filesystem::exists;
using std::filesystem::remove;
using std::filesystem::path;

namespace Utils {

    // String utilities
    string trim(const string& str) {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (first == string::npos) return "";
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, (last - first + 1));
    }

    string toLower(const string& str) {
        string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    string toUpper(const string& str) {
        string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    bool isValidAccountName(const string& name) {
        if (isEmpty(name)) return false;
        if (name.length() > 255) return false;
        // Allow alphanumeric, underscore, and hyphen
        for (char c : name) {
            if (!std::isalnum(c) && c != '_' && c != '-') {
                return false;
            }
        }
        return true;
    }

    bool isValidId(const string& id) {
        return !isEmpty(id) && id.length() <= 512;
    }

    // File utilities
    bool fileExists(const string& filePath) {
        return exists(path(filePath));
    }

    bool deleteFile(const string& filePath) {
        try {
            if (exists(path(filePath))) {
                remove(path(filePath));
                return true;
            }
        } catch (...) {
            return false;
        }
        return false;
    }

    void setSecurePermissions(const string& filePath) {
        chmod(filePath.c_str(), S_IRUSR | S_IWUSR);  // 0600 - owner read/write only
    }

    string getFileExtension(const string& filePath) {
        size_t pos = filePath.find_last_of('.');
        if (pos == string::npos) return "";
        return filePath.substr(pos + 1);
    }

    // Security utilities
    string generateRandomString(size_t length) {
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

        string result;
        for (size_t i = 0; i < length; ++i) {
            result += charset[dis(gen)];
        }
        return result;
    }

    string hashString(const string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (unsigned char*)input.c_str(), input.length());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    // Validation utilities
    bool isEmpty(const string& str) {
        return trim(str).empty();
    }

    bool isNumeric(const string& str) {
        if (isEmpty(str)) return false;
        for (char c : str) {
            if (!std::isdigit(c)) return false;
        }
        return true;
    }

}
