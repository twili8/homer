/*
 * Homer packer stub (layer 1) - x86 (32-bit) variant.
 */
#include "loader.h"

// Distance from the call instruction (self after `self -= 5`) to the body.
// The body is appended at sizeof(.text), and the call sits at .text+7.
#define STUB_SIZE 177

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
        key[i] = (unsigned char)(((seed >> ((i & 3) * 8)) ^ (i * 0x37 + 0x13)) & 0xff);
    }

    for (i = 0; i < body_len; i++) body[i] ^= key[i & 15];

    /* restore the caller's stack frame before handing over */
    __asm__ volatile(
        "movl %%ebp, %%esp\n"
        "popl %%ebp\n"
        "jmp *%0\n" :: "r"(body));
}
