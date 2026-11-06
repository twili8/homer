/*
 * Homer packer stub (layer 1) - variant 2 (x64).
 * Different instruction layout from stub.c to increase polymorphism.
 */
#include "loader.h"

// Distance from the call instruction (self after `self -= 5`) to the body.
// The body is appended at sizeof(.text), and the call sits at .text+8.
#define STUB_SIZE 184

void homer_stub(void) {
    unsigned char *self;
    __asm__ volatile("call 1f\n1:\n pop %0" : "=r"(self));
    self -= 5;

    int seed = 0xDEADBEEF;
    int body_len = 0xDEADBEEF;
    unsigned char *body = self + STUB_SIZE;

    unsigned char key[16];
    int i;
    /* different key derivation (multiply instead of xor-shift) */
    for (i = 0; i < 16; i++) {
        key[i] = (unsigned char)((seed * (i + 7) + 0x5a827999) & 0xff);
    }

    /* decrypt with a different loop structure */
    for (i = 0; i < body_len; i++) {
        body[i] ^= key[i & 15];
    }

    /* restore the caller's stack frame before handing over */
    __asm__ volatile(
        "mov %%rbp, %%rsp\n"
        "pop %%rbp\n"
        "jmp *%0\n" :: "r"(body));
}
