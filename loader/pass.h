/* Homer operator passes.
 *
 * The loader core decrypts, maps, binds and jumps. Everything else is a
 * pass. A pass is a freestanding function compiled into the loader that runs
 * at one of two points:
 *
 *   HOMER_PRE_MAP  - after the bootstrap decrypt/MAC check and the instance
 *                    copy, before any loader API is resolved or any section
 *                    is mapped. Only inst is valid; mod/base/nt are NULL.
 *   HOMER_PRE_JUMP - after the image is bound (imports resolved), while it
 *                    is still writable, before headers are wiped, section
 *                    protections are set, TLS callbacks run, or any entry
 *                    point is invoked. All four arguments are valid.
 *                    PE payloads only: raw shellcode has no image and no
 *                    jump point to hook.
 *
 * Passes resolve everything through the PEB (inst->api,
 * xGetProcAddressByHash). A direct Win32 call would add an import to the
 * release artifact; tools/gen_passes.py rejects both the source pattern and
 * the resulting import table.
 *
 * A pass returns 0 to continue the load, nonzero to abort it. Abort is fail
 * closed: the caller wipes the instance and returns without jumping.
 */

#ifndef HOMER_PASS_H
#define HOMER_PASS_H

/* loader.h first: it defines LOADER_H, which keeps donut.h from defining
 * its own DPRINT. pass.h alone is all a pass file needs to include. */
#include "loader.h"

typedef enum {
    HOMER_PRE_MAP = 0,
    HOMER_PRE_JUMP = 1
} homer_stage_t;

typedef int (*homer_pass_fn)(PDONUT_INSTANCE inst, PDONUT_MODULE mod,
                             PVOID base, PIMAGE_NT_HEADERS nt);

typedef struct {
    const char *name;
    homer_stage_t stage;
    homer_pass_fn run;
} homer_pass_t;

/* Pass runner. Provided by build/passes_gen.c, generated from passes/ by
 * tools/gen_passes.py. A direct-call dispatcher, not a pointer table: the
 * release loader runs as unrelocated PIC shellcode, so absolute addresses
 * in .rdata would be garbage. Direct calls are RIP-relative and safe. */
int homer_run_passes(homer_stage_t stage, PDONUT_INSTANCE inst,
                     PDONUT_MODULE mod, PVOID base, PIMAGE_NT_HEADERS nt);

/* Marker macro. Expands to nothing; tools/gen_passes.py parses it and emits
 * the table entry. One marker per pass, in the same file that defines
 * int homer_pass__<name>(PDONUT_INSTANCE, PDONUT_MODULE, PVOID,
 * PIMAGE_NT_HEADERS). */
#define HOMER_REGISTER(n, s) /* wired by tools/gen_passes.py */

#endif
