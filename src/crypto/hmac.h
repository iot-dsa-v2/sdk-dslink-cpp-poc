#ifndef DSA_SDK_CRYPTO_HMAC_H_
#define DSA_SDK_CRYPTO_HMAC_H_

#include <vector>

#include <openssl/hmac.h>

#include "util.h"

namespace dsa {
class hmac {
 private:
  // HMAC_CTX *ctx;
  HMAC_CTX ctx;
  bool initialized;

 public:
  hmac(const char *alg, Buffer& to_hash);
  ~hmac();

  void init(const char *alg, Buffer& to_hash);
  void update(Buffer& data);
  std::shared_ptr<Buffer> digest();
};
}  // namespace dsa

#endif  // DSA_SDK_CRYPTO_HMAC_H_