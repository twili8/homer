#ifndef HOMER_KDF_H
#define HOMER_KDF_H

#include <stdint.h>
#include <string.h>

/* ROTR32 may already be defined by hash.h; define if missing */
#ifndef ROTR32
#define ROTR32(v,n)(((v)>>(n))|((v)<<(32-(n))))
#endif

/*
 * Homer bootstrap KDF (layers 4/5) -- SPECK-64/128 based.
 *
 * Replaces the previous maru (64-bit hash) based mask with a proper
 * block-cipher (SPECK) based KDF for better diffusion. The salt (16 bytes)
 * is the 128-bit key; each mask is one SPECK encryption of a
 * domain-separated counter block.
 *
 * Shared verbatim between the generator (donut.c) and the loader so
 * masking/unmasking can never drift. The salt is a per-build constant baked
 * into the (packed, encrypted-at-rest) loader; every field of the plaintext
 * bootstrap prefix is XORed with a value derived from it.
 */
#define HOMER_SALT_INIT { \
    0xc6, 0xe5, 0xce, 0x81, 0x7e, 0xca, 0x88, 0xd9, \
    0xa3, 0xcb, 0x25, 0x82, 0x7d, 0x14, 0x73, 0x9e  \
}

/* SPECK-64/128: 64-bit block, 128-bit key, 27 rounds */
static inline uint64_t homer_speck(const uint8_t key[16], uint64_t plaintext) {
    uint32_t k[4], i, t;
    uint32_t x0, x1;
    for (i = 0; i < 4; i++) k[i] = ((uint32_t*)key)[i];
    x0 = (uint32_t)(plaintext);
    x1 = (uint32_t)(plaintext >> 32);
    for (i = 0; i < 27; i++) {
        x0 = (ROTR32(x0, 8) + x1) ^ k[0];
        x0 &= 0xffffffff;
        x1 = ROTR32(x1, 29) ^ x0;
        x1 &= 0xffffffff;
        t = k[3];
        k[3] = (ROTR32(k[1], 8) + k[0]) ^ i;
        k[3] &= 0xffffffff;
        k[0] = ROTR32(k[0], 29) ^ k[3];
        k[0] &= 0xffffffff;
        k[1] = k[2];
        k[2] = t;
    }
    return ((uint64_t)x1 << 32) | x0;
}

/* Derive a 16-byte mask for a given domain index (0,1,2) */
static inline void homer_kdf(int which, uint8_t out[16]) {
    volatile uint8_t salt[16];
    uint64_t v0, v1;
    /* byte-wise init keeps salt as immediates in .text (no .rdata ref) */
    salt[0]=0xc6; salt[1]=0xe5; salt[2]=0xce; salt[3]=0x81;
    salt[4]=0x7e; salt[5]=0xca; salt[6]=0x88; salt[7]=0xd9;
    salt[8]=0xa3; salt[9]=0xcb; salt[10]=0x25; salt[11]=0x82;
    salt[12]=0x7d; salt[13]=0x14; salt[14]=0x73; salt[15]=0x9e;
    /* domain separation: mix 'which' into the key */
    salt[0] ^= (uint8_t)(which * 0x37 + 0x13);
    salt[8] ^= (uint8_t)(which * 0x59 + 0x2d);
    v0 = homer_speck((const uint8_t *)salt, 0x9e3779b97f4a7c15ULL ^ ((uint64_t)which * 0x9e3779b9));
    v1 = homer_speck((const uint8_t *)salt, 0xd1b54a32d192ed03ULL ^ ((uint64_t)which * 0x7f4a7c15));
    memcpy(out, &v0, 8);
    memcpy(out + 8, &v1, 8);
}

#define HOMER_KDF_LEN 0
#define HOMER_KDF_IV  1
#define HOMER_KDF_MK  2

/* XOR a bootstrap field with its KDF-derived mask (involution). */
static inline void homer_mask_xor(uint8_t *field, uint32_t flen, int which) {
    uint8_t m[16];
    uint32_t i;
    homer_kdf(which, m);
    for (i = 0; i < flen; i++) field[i] ^= m[i % 16];
}

#endif
