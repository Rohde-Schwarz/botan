#!/usr/bin/env python3
"""
DTLS 1.3 cipher-state test vector generator.
Produces golden hex values for test_tls_dtls13_cipher_state.cpp.

Cipher suite : AES_128_GCM_SHA256  (SHA-256 / AES-128 / 12-byte IV)
Inputs       : all-zero shared_secret and transcript_hash for reproducibility.
"""
import hashlib, hmac, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── HKDF primitives ──────────────────────────────────────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes, h: str = 'sha256') -> bytes:
    return hmac.new(salt, ikm, h).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, h: str = 'sha256') -> bytes:
    hash_len = hashlib.new(h).digest_size
    n = (length + hash_len - 1) // hash_len
    okm, t = b'', b''
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
    return okm[:length]

def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      length: int, h: str = 'sha256') -> bytes:
    # RFC 9147 §5.9: "dtls13" (no trailing space, same 6-byte width as "tls13 ")
    full_label = b'dtls13' + label.encode('ascii')
    hkdf_label = (struct.pack('>H', length)
                  + bytes([len(full_label)]) + full_label
                  + bytes([len(context)]) + context)
    return hkdf_expand(secret, hkdf_label, length, h)

def derive_secret(secret: bytes, label: str, transcript: bytes,
                  h: str = 'sha256') -> bytes:
    return hkdf_expand_label(secret, label, transcript,
                             hashlib.new(h).digest_size, h)

# ── Parameters ────────────────────────────────────────────────────────────────

HASH_LEN = 32
KEY_LEN  = 16   # AES-128
IV_LEN   = 12
EPOCH    = 2    # handshake epoch in DTLS 1.3  (RFC 9147 §5.8)
SEQ_NO   = 0

shared_secret   = bytes(32)   # 32 zero bytes
transcript_hash = bytes(32)   # Hash(ClientHello || ServerHello) – zeros for test

# ── Key schedule (RFC 8446 §7.1 with "dtls13" labels) ────────────────────────

early_secret = hkdf_extract(bytes(HASH_LEN), bytes(HASH_LEN))
# "derived" uses hash of empty string as context (RFC 8446 §7.1)
derived      = derive_secret(early_secret, 'derived', hashlib.sha256(b'').digest())
hs_secret    = hkdf_extract(derived, shared_secret)

c_hs_traffic = derive_secret(hs_secret, 'c hs traffic', transcript_hash)
s_hs_traffic = derive_secret(hs_secret, 's hs traffic', transcript_hash)

# Server sends → derive key material from s_hs_traffic
s_key    = hkdf_expand_label(s_hs_traffic, 'key', b'', KEY_LEN)
s_iv     = hkdf_expand_label(s_hs_traffic, 'iv',  b'', IV_LEN)
s_sn_key = hkdf_expand_label(s_hs_traffic, 'sn',  b'', KEY_LEN)  # DTLS-only

# ── SN masking: AES-128-ECB(sn_key, ciphertext_sample) ───────────────────────
# RFC 9147 §4.2.3

ct_sample = bytes(16)   # first 16 bytes of ciphertext – zeros for a known input
ecb       = Cipher(algorithms.AES(s_sn_key), modes.ECB()).encryptor()
sn_mask   = ecb.update(ct_sample) + ecb.finalize()

# ── AEAD: server encrypts "hello dtls" (epoch=2, seq_no=0) ───────────────────
# RFC 9147 §4.2.2, RFC 8446 §5.3

PLAINTEXT = b'hello dtls'

# Unified header (RFC 9147 §4.2): C=0 S=0(8-bit seq) L=0 EE=(epoch & 3)=2
# Byte 0: 0b 001 C S L EE  →  0b 00100010 = 0x22
# Byte 1: seq_no (encrypted on the wire; we test with unmasked=0x00 here)
unified_header = bytes([0x22, SEQ_NO & 0xFF])

nonce_raw = b'\x00\x00\x00\x00' + struct.pack('>Q', SEQ_NO)
nonce      = bytes(a ^ b for a, b in zip(nonce_raw, s_iv))

ciphertext = AESGCM(s_key).encrypt(nonce, PLAINTEXT, unified_header)

# ── Print golden values ───────────────────────────────────────────────────────

def fmt(data: bytes) -> str:
    h = data.hex()
    return ' '.join(h[i:i+2] for i in range(0, len(h), 2))

print('# DTLS 1.3 / AES_128_GCM_SHA256 – all-zero inputs\n')
print(f'shared_secret   = {fmt(shared_secret)}')
print(f'transcript_hash = {fmt(transcript_hash)}\n')
print(f'c_hs_traffic    = {fmt(c_hs_traffic)}')
print(f's_hs_traffic    = {fmt(s_hs_traffic)}\n')
print(f's_key           = {fmt(s_key)}')
print(f's_iv            = {fmt(s_iv)}')
print(f's_sn_key        = {fmt(s_sn_key)}\n')
print(f'ct_sample       = {fmt(ct_sample)}  (16 zero bytes)')
print(f'sn_mask         = {fmt(sn_mask)}\n')
print(f'epoch           = {EPOCH}')
print(f'seq_no          = {SEQ_NO}')
print(f'unified_header  = {fmt(unified_header)}')
print(f'nonce_raw       = {fmt(nonce_raw)}')
print(f'nonce           = {fmt(nonce)}')
print(f'plaintext       = {fmt(PLAINTEXT)}')
print(f'ciphertext      = {fmt(ciphertext)}')
