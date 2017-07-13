#ifndef DSA_SDK_CRYPTO_ECDH_H_
#define DSA_SDK_CRYPTO_ECDH_H_

#include <vector>
#include <memory>

#include <openssl/ec.h>

#include "util.h"

namespace dsa {
class ecdh {
 private:
  EC_KEY *key;
  const EC_GROUP *group;
  bool is_key_valid_for_curve(BIGNUM *private_key);

 public:
  ecdh(const char *curve);
  ~ecdh();

  std::shared_ptr<Buffer> get_private_key();
  std::shared_ptr<Buffer> get_public_key();
  std::shared_ptr<Buffer> compute_secret(Buffer& public_key);
  void set_private_key_hex(const char *data);
};
}  // namespace dsa

#endif  // DSA_SDK_CRYPTO_ECDH_H_