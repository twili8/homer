/*
 * Homer packer stub (layer 1).
 *
 * Freestanding, position-independent. Runs from the RWX buffer the loader
 * (or injector) hands us. XOR-decrypts the body that follows it in the same
 * buffer, then jumps to it. No libc, no .rdata references: every constant is
 * an immediate so the whole stub survives verbatim extraction from .text.
 *
 * Placeholders patched per generation by the generator:
 *   0xde 0xad 0xbe 0xef  (uint32, LE) at BODYLEN_OFF  -> body length
 *   0xde 0xad 0xbe 0xef  (uint32, LE) at SEED_OFF    -> per-generation seed
 */
#include "loader.h"

// Distance from the call instruction (self after `self -= 5`) to the body.
// The body is appended at sizeof(.text), and the call sits at .text+8.
#define STUB_SIZE 200

void homer_stub(void) {
    unsigned char *self;
    __asm__ volatile("call 1f\n1:\n pop %0" : "=r"(self));
    self -= 5;

    int seed = 0xDEADBEEF;
    int body_len = 0xDEADBEEF;
    unsigned char *body = self + STUB_SIZE;

    unsigned char key[16];
    int i;
    for (i = 0; i < 16; i++) {
        key[i] = (unsigned char)((seed >> ((i & 3) * 8)) ^ (i * 0x37 + 0x13));
    }

    /* in-place XOR (stream cipher; key repeats) */
    for (i = 0; i < body_len; i++) body[i] ^= key[i & 15];

    /* restore the caller's stack frame before handing over */
    __asm__ volatile(
        "mov %%rbp, %%rsp\n"
        "pop %%rbp\n"
        "jmp *%0\n" :: "r"(body));
}
