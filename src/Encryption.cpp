#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cstring>

using std::string;

#include "encryption.h"

static inline void ensureOpensslSuccess(bool ok, const char* msg) {
    if (!ok) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        throw std::runtime_error(std::string(msg) + ": " + buf);
    }
}

static inline string toHex(const string& bin) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned char c : bin) {
        hex << std::setw(2) << static_cast<int>(c);
    }
    return hex.str();
}

static inline string fromHex(const string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }
    string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        out.push_back(static_cast<char>(byte));
    }
    return out;
}

static inline string base64Encode(const string& bin) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    BIO_write(b64, bin.data(), static_cast<int>(bin.size()));
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    string out(bptr->data, bptr->length);

    BIO_free_all(b64);
    return out;
}

static inline string base64Decode(const string& b64) {
    BIO* bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    BIO* b64f = BIO_new(BIO_f_base64());
    BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64f, bio);

    std::vector<char> buffer(b64.size());
    int len = BIO_read(b64f, buffer.data(), static_cast<int>(buffer.size()));
    if (len < 0) {
        BIO_free_all(b64f);
        throw std::runtime_error("Base64 decode failure");
    }

    BIO_free_all(b64f);
    return string(buffer.data(), len);
}

string AESEncryption::encrypt(const string& data, const string& key) {
    if (key.empty()) {
        throw std::invalid_argument("AES key is empty");
    }

    unsigned char aesKey[32]; // AES-256
    unsigned char aesIv[16];

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                        reinterpret_cast<const unsigned char*>(key.data()),
                        static_cast<int>(key.size()), 1,
                        aesKey, aesIv)) {
        throw std::runtime_error("EVP_BytesToKey failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    ensureOpensslSuccess(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIv) == 1,
                         "EVP_EncryptInit_ex");

    string cipher;
    cipher.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int outLen1 = 0;
    ensureOpensslSuccess(EVP_EncryptUpdate(ctx,
                                          reinterpret_cast<unsigned char*>(&cipher[0]),
                                          &outLen1,
                                          reinterpret_cast<const unsigned char*>(data.data()),
                                          static_cast<int>(data.size())) == 1,
                         "EVP_EncryptUpdate");

    int outLen2 = 0;
    ensureOpensslSuccess(EVP_EncryptFinal_ex(ctx,
                                             reinterpret_cast<unsigned char*>(&cipher[0]) + outLen1,
                                             &outLen2) == 1,
                         "EVP_EncryptFinal_ex");

    EVP_CIPHER_CTX_free(ctx);

    cipher.resize(outLen1 + outLen2);
    string ivStr(reinterpret_cast<char*>(aesIv), sizeof(aesIv));

    return toHex(ivStr + cipher);
}

string AESEncryption::decrypt(const string& data, const string& key) {
    if (key.empty()) {
        throw std::invalid_argument("AES key is empty");
    }

    string encrypted = fromHex(data);
    if (encrypted.size() < 16) {
        throw std::invalid_argument("Encrypted data too short");
    }

    unsigned char aesKey[32];
    unsigned char aesIv[16];
    std::memcpy(aesIv, encrypted.data(), 16);
    string cipher = encrypted.substr(16);

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                        reinterpret_cast<const unsigned char*>(key.data()),
                        static_cast<int>(key.size()), 1,
                        aesKey, aesIv)) {
        throw std::runtime_error("EVP_BytesToKey failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    ensureOpensslSuccess(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIv) == 1,
                         "EVP_DecryptInit_ex");

    string plaintext;
    plaintext.resize(cipher.size());

    int outLen1 = 0;
    ensureOpensslSuccess(EVP_DecryptUpdate(ctx,
                                          reinterpret_cast<unsigned char*>(&plaintext[0]),
                                          &outLen1,
                                          reinterpret_cast<const unsigned char*>(cipher.data()),
                                          static_cast<int>(cipher.size())) == 1,
                         "EVP_DecryptUpdate");

    int outLen2 = 0;
    ensureOpensslSuccess(EVP_DecryptFinal_ex(ctx,
                                             reinterpret_cast<unsigned char*>(&plaintext[0]) + outLen1,
                                             &outLen2) == 1,
                         "EVP_DecryptFinal_ex");

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen1 + outLen2);
    return plaintext;
}

string RSAEncryption::encrypt(const string& data, const string& key) {
    BIO* bio = BIO_new_mem_buf(key.data(), static_cast<int>(key.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for RSA public key");
    }

    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        throw std::runtime_error("Failed to load RSA public key");
    }

    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> out(rsaSize);
    int encryptedLen = RSA_public_encrypt(static_cast<int>(data.size()),
                                          reinterpret_cast<const unsigned char*>(data.data()),
                                          out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (encryptedLen <= 0) {
        throw std::runtime_error("RSA_public_encrypt failed");
    }

    return base64Encode(string(reinterpret_cast<char*>(out.data()), encryptedLen));
}

string RSAEncryption::decrypt(const string& data, const string& key) {
    string bin = base64Decode(data);

    BIO* bio = BIO_new_mem_buf(key.data(), static_cast<int>(key.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for RSA private key");
    }

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        throw std::runtime_error("Failed to load RSA private key");
    }

    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> out(rsaSize);
    int decryptedLen = RSA_private_decrypt(static_cast<int>(bin.size()),
                                           reinterpret_cast<const unsigned char*>(bin.data()),
                                           out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (decryptedLen <= 0) {
        throw std::runtime_error("RSA_private_decrypt failed");
    }

    return string(reinterpret_cast<char*>(out.data()), decryptedLen);
}

string DESEncryption::encrypt(const string& data, const string& key) {
    if (key.empty()) {
        throw std::invalid_argument("DES key is empty");
    }

    unsigned char desKey[8] = {0};
    unsigned char desIv[8] = {0};
    std::memcpy(desKey, key.data(), std::min<size_t>(key.size(), 8));
    std::memcpy(desIv, key.data(), std::min<size_t>(key.size(), 8));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    ensureOpensslSuccess(EVP_EncryptInit_ex(ctx, EVP_des_cbc(), nullptr, desKey, desIv) == 1,
                         "EVP_EncryptInit_ex");

    string cipher;
    cipher.resize(data.size() + EVP_CIPHER_block_size(EVP_des_cbc()));

    int outLen1 = 0;
    ensureOpensslSuccess(EVP_EncryptUpdate(ctx,
                                          reinterpret_cast<unsigned char*>(&cipher[0]),
                                          &outLen1,
                                          reinterpret_cast<const unsigned char*>(data.data()),
                                          static_cast<int>(data.size())) == 1,
                         "EVP_EncryptUpdate");

    int outLen2 = 0;
    ensureOpensslSuccess(EVP_EncryptFinal_ex(ctx,
                                             reinterpret_cast<unsigned char*>(&cipher[0]) + outLen1,
                                             &outLen2) == 1,
                         "EVP_EncryptFinal_ex");

    EVP_CIPHER_CTX_free(ctx);
    cipher.resize(outLen1 + outLen2);
    return base64Encode(cipher);
}

string DESEncryption::decrypt(const string& data, const string& key) {
    if (key.empty()) {
        throw std::invalid_argument("DES key is empty");
    }

    string cipher = base64Decode(data);

    unsigned char desKey[8] = {0};
    unsigned char desIv[8] = {0};
    std::memcpy(desKey, key.data(), std::min<size_t>(key.size(), 8));
    std::memcpy(desIv, key.data(), std::min<size_t>(key.size(), 8));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    ensureOpensslSuccess(EVP_DecryptInit_ex(ctx, EVP_des_cbc(), nullptr, desKey, desIv) == 1,
                         "EVP_DecryptInit_ex");

    string plaintext;
    plaintext.resize(cipher.size());

    int outLen1 = 0;
    ensureOpensslSuccess(EVP_DecryptUpdate(ctx,
                                          reinterpret_cast<unsigned char*>(&plaintext[0]),
                                          &outLen1,
                                          reinterpret_cast<const unsigned char*>(cipher.data()),
                                          static_cast<int>(cipher.size())) == 1,
                         "EVP_DecryptUpdate");

    int outLen2 = 0;
    ensureOpensslSuccess(EVP_DecryptFinal_ex(ctx,
                                             reinterpret_cast<unsigned char*>(&plaintext[0]) + outLen1,
                                             &outLen2) == 1,
                         "EVP_DecryptFinal_ex");

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen1 + outLen2);
    return plaintext;
}