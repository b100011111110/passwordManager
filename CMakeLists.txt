cmake_minimum_required(VERSION 3.10)
project(PasswordManager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(/usr/include)  # for nlohmann/json

# Runtime dependencies (must be installed):
#   sudo apt install tpm2-tools libsecret-tools

add_executable(passwordManager
    src/main.cpp
    src/tools/Manager.cpp
    src/tools/MasterKeyManager.cpp
    src/tools/Accounts.cpp
    src/encryption/Encryption.cpp
)

target_link_libraries(passwordManager OpenSSL::SSL OpenSSL::Crypto)
