#pragma once

#include <string>
#include <vector>
#include <array>
#include <iostream>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef unsigned char byte;

#ifndef uint
typedef unsigned int uint;
#endif

namespace dsa {
  class ecdh {
  private:
    EC_KEY *key;
    const EC_GROUP *group;
    bool is_key_valid_for_curve(BIGNUM *private_key);

  public:
    ecdh(const char *curve);
    ~ecdh();
    
    std::vector<byte> get_private_key();
    std::vector<byte> get_public_key();
    std::vector<byte> compute_secret(std::vector<byte> public_key);
    void set_private_key_hex(const char *data);
  };

  class hash {
  private:
    EVP_MD_CTX mdctx;
    bool finalized;

    // hack-ish static initialization 
    class Init {
    public:
      Init() {
        OpenSSL_add_all_digests();
      }
    };
    Init init;

  public:
    hash(const char *hash_type);
    ~hash();

    void update(std::vector<byte> data);
    std::string digest_base64();
  };

  class hmac {
  private:
    // HMAC_CTX *ctx;
    HMAC_CTX ctx;
    bool initialized;

  public:
    hmac(const char *alg, std::vector<byte> to_hash);
    ~hmac();

    void init(const char *alg, std::vector<byte> to_hash);
    void update(std::vector<byte> data);
    std::vector<byte> digest();
  };

  std::string base64url(std::string str);
  std::string base64_decode(std::string const& encoded_string);
  std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
  std::vector<byte> gen_salt(int len);
  std::vector<byte> hex2bin(const char *src);
}

template <typename T>
inline std::ostream& operator << (std::ostream& os, const std::vector<T>& v) {
  os << "[";
  if (v.size() > 0) {
    for (int i = 0; i < v.size() - 1; ++i)
      os << v[i] << ", ";
    os << v[v.size() - 1];
  }
  os << "]";
  return os;  
}

inline std::ostream& operator << (std::ostream& os, const std::vector<byte>& v) {
  std::stringstream ss;
  ss << "[";
  if (v.size() > 0) {
    for (int i = 0; i < v.size() - 1; ++i) {
      ss << "x";
      if (v[i] < 0x10) ss << 0;
      ss << std::hex << (uint)v[i] << std::dec << ", ";
    }
    uint last = v[v.size() - 1];
    ss << "x" << (last < 0x10 ? "0" : "") << std::hex << last << std::dec;
  }
  ss << "]";
  return os << ss.str();  
}

template <typename T, int S>
inline std::ostream& operator << (std::ostream& os, const std::array<T, S>& v) {
  os << "[";
  if (v.size() > 0) {
    for (int i = 0; i < v.size() - 1; ++i)
      os << v[i] << ", ";
    os << v[v.size() - 1];
  }
  os << "]";
  return os;  
}

template <int S>
inline std::ostream& operator << (std::ostream& os, const std::array<byte, S>& v) {
  std::stringstream ss;
  ss << "[";
  if (v.size() > 0) {
    for (int i = 0; i < v.size() - 1; ++i) {
      ss << "x";
      if (v[i] < 0x10) ss << 0;
      ss << std::hex << (uint)v[i] << std::dec << ", ";
    }
    uint last = v[v.size() - 1];
    ss << "x" << (last < 0x10 ? "0" : "") << std::hex << last << std::dec;
  }
  ss << "]";
  return os << ss.str();  
}