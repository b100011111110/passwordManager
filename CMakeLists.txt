cmake_minimum_required(VERSION 3.10)
project(PasswordManager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(/usr/include)  # for nlohmann/json

add_executable(passwordManager
    src/main.cpp
    src/Manager.cpp
    src/Accounts.cpp
    src/Encryption.cpp
)

target_link_libraries(passwordManager OpenSSL::SSL OpenSSL::Crypto)