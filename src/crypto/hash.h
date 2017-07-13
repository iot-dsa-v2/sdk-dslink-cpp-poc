#ifndef DSA_SDK_CRYPTO_HASH_H_
#define DSA_SDK_CRYPTO_HASH_H_

#include <vector>

#include <openssl/evp.h>

#include "util.h"

namespace dsa {
class hash {
 private:
  EVP_MD_CTX mdctx;
  bool finalized;

  // hack-ish static initialization
  class Init {
   public:
    Init() { OpenSSL_add_all_digests(); }
  };
  Init init;

 public:
  hash(const char *hash_type);
  ~hash();

  void update(Buffer& data);
  std::string digest_base64();
};
}  // namespace dsa

#endif  // DSA_SDK_CRYPTO_HASH_H_