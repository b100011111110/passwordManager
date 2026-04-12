#include <cstring>
#include <iomanip>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <vector>

using std::string;

#include "encryption.h"

// RAII wrapper for EVP_CIPHER_CTX
struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX *ctx) const {
    if (ctx)
      EVP_CIPHER_CTX_free(ctx);
  }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

static inline void ensureOpensslSuccess(bool ok, const char *msg) {
  if (!ok) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(std::string(msg) + ": " + buf);
  }
}

static inline string toHex(const string &bin) {
  std::ostringstream hex;
  hex << std::hex << std::setfill('0');
  for (unsigned char c : bin) {
    hex << std::setw(2) << static_cast<int>(c);
  }
  return hex.str();
}

static inline string fromHex(const string &hex) {
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

// AES encryption with vector-based key (already derived via PBKDF2)
string AESEncryption::encrypt(const string &data,
                              const std::vector<unsigned char> &key) {
  if (key.empty() || key.size() != 32) {
    throw std::invalid_argument("AES key must be exactly 32 bytes");
  }

  // Generate random IV (16 bytes)
  unsigned char aesIv[16];
  if (!RAND_bytes(aesIv, sizeof(aesIv))) {
    throw std::runtime_error("RAND_bytes failed");
  }

  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  ensureOpensslSuccess(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                                          key.data(), aesIv) == 1,
                       "EVP_EncryptInit_ex");

  string cipher;
  cipher.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

  int outLen1 = 0;
  ensureOpensslSuccess(
      EVP_EncryptUpdate(ctx.get(),
                        reinterpret_cast<unsigned char *>(&cipher[0]), &outLen1,
                        reinterpret_cast<const unsigned char *>(data.data()),
                        static_cast<int>(data.size())) == 1,
      "EVP_EncryptUpdate");

  int outLen2 = 0;
  ensureOpensslSuccess(
      EVP_EncryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(&cipher[0]) + outLen1,
          &outLen2) == 1,
      "EVP_EncryptFinal_ex");

  cipher.resize(outLen1 + outLen2);
  string ivStr(reinterpret_cast<char *>(aesIv), sizeof(aesIv));

  return toHex(ivStr + cipher);
}

string AESEncryption::decrypt(const string &data,
                              const std::vector<unsigned char> &key) {
  if (key.empty() || key.size() != 32) {
    throw std::invalid_argument("AES key must be exactly 32 bytes");
  }

  string encrypted = fromHex(data);
  if (encrypted.size() < 16) {
    throw std::invalid_argument("Encrypted data too short");
  }

  unsigned char aesIv[16];
  std::memcpy(aesIv, encrypted.data(), 16);
  string cipher = encrypted.substr(16);

  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  ensureOpensslSuccess(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                                          key.data(), aesIv) == 1,
                       "EVP_DecryptInit_ex");

  string plaintext;
  plaintext.resize(cipher.size());

  int outLen1 = 0;
  ensureOpensslSuccess(
      EVP_DecryptUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(&plaintext[0]), &outLen1,
          reinterpret_cast<const unsigned char *>(cipher.data()),
          static_cast<int>(cipher.size())) == 1,
      "EVP_DecryptUpdate");

  int outLen2 = 0;
  ensureOpensslSuccess(
      EVP_DecryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(&plaintext[0]) + outLen1,
          &outLen2) == 1,
      "EVP_DecryptFinal_ex");

  plaintext.resize(outLen1 + outLen2);

  return plaintext;
}
