/*
 * Crystals Kyber key encapsulation mechanism
 *
 * Strong Type definitions used throughout the Kyber implementation
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_TYPES_H_
#define BOTAN_DILITHIUM_TYPES_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>

#include <vector>

namespace Botan {

/// Principal seed used to generate Dilithium key pairs
using DilithiumSeedRandomness = Strong<secure_vector<uint8_t>, struct DilithiumSeedRandomness_>;

/// Public seed to sample the polynomial matrix A from
using DilithiumSeedRho = Strong<std::vector<uint8_t>, struct DilithiumPublicSeed_>;

/// Private seed to sample the polynomial vectors s1 and s2 from
using DilithiumSeedRhoPrime = Strong<secure_vector<uint8_t>, struct DilithiumSeedRhoPrime_>;

/// Private seed K used during signing
/// TODO: perhaps find a better name later
using DilithiumSeedK = Strong<secure_vector<uint8_t>, struct DilithiumSeedK_>;

/// H(pkEncode(pk)) used during signing
// TODO: perhaps find a better name later
// TODO: that's the hash of the public key and should therefor be a std::vector, no?
using DilithiumTR = Strong<secure_vector<uint8_t>, struct DilithiumTR_>;

/// Serialized public key data (result of pkEncode(pk))
using DilithiumSerializedPublicKey = Strong<std::vector<uint8_t>, struct DilithiumSerializedPublicKey_>;

/// Hash value of the serialized public key data (result of H(BytesToBits(pkEncode(pk)))
using DilithiumHashedPublicKey = Strong<std::vector<uint8_t>, struct DilithiumHashedPublicKey_>;

}  // namespace Botan

#endif
