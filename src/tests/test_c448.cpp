/*
 * Curve448 Tests
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_CURVE_448)

   #include "test_pubkey.h"
   #include <botan/curve448.h>

namespace Botan_Tests {

namespace {

class Curve448_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {""}; }

      std::string algo_name() const override { return "Curve448"; }
};

class Curve448_Agreement_Tests final : public PK_Key_Agreement_Test {
   public:
      Curve448_Agreement_Tests() : PK_Key_Agreement_Test("X448", "pubkey/x448.vec", "Secret,CounterKey,K") {}

      std::string default_kdf(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> secret_vec = vars.get_req_bin("Secret");
         const Botan::secure_vector<uint8_t> secret(secret_vec.begin(), secret_vec.end());
         return std::make_unique<Botan::Curve448_PrivateKey>(secret);
      }

      std::vector<uint8_t> load_their_key(const std::string& /*header*/, const VarMap& vars) override {
         return vars.get_req_bin("CounterKey");
      }
};

}  // namespace

BOTAN_REGISTER_TEST("curve448", "curve448_keygen", Curve448_Keygen_Tests);
BOTAN_REGISTER_TEST("curve448", "curve448_agree", Curve448_Agreement_Tests);

}  // namespace Botan_Tests
#endif  // BOTAN_HAS_CURVE_448
