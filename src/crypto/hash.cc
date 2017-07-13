#include "hash.h"

#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#include <openssl/evp.h>

#include "misc.h"

namespace dsa {
hash::hash(const char *hash_type) : finalized(false) {
  const EVP_MD *md = EVP_get_digestbyname(hash_type);
  if (md == nullptr) throw std::runtime_error("invalid hash type");
  // mdctx = EVP_MD_CTX_create();
  EVP_MD_CTX_init(&mdctx);
  if (EVP_DigestInit_ex(&mdctx, md, nullptr) <= 0)
    throw std::runtime_error("something went wrong initializing digest");
}

hash::~hash() {
  // EVP_MD_CTX_destroy(mdctx);
}

void hash::update(Buffer& content) {
  EVP_DigestUpdate(&mdctx, content.data(), content.size());
}

std::string hash::digest_base64() {
  if (finalized) throw std::runtime_error("digest already called");

  uint8_t md_value[EVP_MAX_MD_SIZE];
  uint md_len;
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  finalized = true;

  EVP_MD_CTX_cleanup(&mdctx);

  std::string out = base64_encode(md_value, md_len);
  return out;
}
}  // namespace dsa
