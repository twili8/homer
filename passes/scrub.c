/* Operator pass: import-name scrubbing.
 *
 * Runs at HOMER_PRE_JUMP, after imports are bound while the image is still
 * writable, before headers are wiped and protections are set. Zeroes the
 * hint/name and DLL-name strings in the mapped copy; the disk image and
 * directory RVAs are untouched, so binding still works.
 */

#include "pass.h"
#include "loader.h"

int homer_pass__scrub(PDONUT_INSTANCE inst, PDONUT_MODULE mod,
                      PVOID base, PIMAGE_NT_HEADERS nt) {
    (void)inst;
    (void)mod;
    if (base == NULL || nt == NULL) return -1;
    ScrubImportNames((PCHAR)base, nt);
    return 0;
}

HOMER_REGISTER(scrub, HOMER_PRE_JUMP)
