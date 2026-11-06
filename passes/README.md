# Operator passes

The loader core decrypts, maps, binds and jumps. Everything else is a pass in
this directory. A pass is one marker plus one function:

```c
#include "pass.h"

int homer_pass__myname(PDONUT_INSTANCE inst, PDONUT_MODULE mod,
                       PVOID base, PIMAGE_NT_HEADERS nt) {
    /* ... */
    return 0; /* nonzero aborts the load, fail closed */
}

HOMER_REGISTER(myname, HOMER_PRE_MAP)
```

Stages:

- `HOMER_PRE_MAP` runs after the bootstrap decrypt/MAC check and the
  instance copy, before any loader API is resolved. Only `inst` is valid;
  `mod`, `base` and `nt` are NULL.
- `HOMER_PRE_JUMP` runs after the PE image is bound (imports resolved),
  while it is still writable: before headers are wiped, protections are set,
  TLS callbacks run, or any entry point is invoked. All four arguments are
  valid. PE payloads only: raw shellcode has no image and no jump point to
  hook.

Build: `tools/gen_passes.py` scans this directory for `HOMER_REGISTER`
markers and emits a direct-call dispatcher into `build/c/passes_gen.c`. There is
no runtime registry and no pass limit. One marker per pass, one file per pass
convention (the build accepts several markers per file, sorted by stage).

Rules, enforced by the build:

- PEB only. Resolve everything through `inst->api` or
  `xGetProcAddressByHash`. Direct Win32 calls (`LoadLibrary`,
  `GetProcAddress`, `VirtualAlloc`, `CreateThread`, …), `dllimport` and
  `#pragma comment(lib)` fail the source gate; any import table in the
  release artifact fails `--check-imports`.
- Freestanding. No CRT, no exceptions, no RTTI. C++ files must wrap the
  pass function in `extern "C"` and get `-fno-exceptions -fno-rtti`.
- String literals land in `.rdata`, which the release loader appends. Code
  that runs before that mapping exists (bootstrap-adjacent passes) must build
  names on the stack; see the stack-built `ntdll.dll` block in
  `loader/peb.c` (`homer_get_proc`) and its use in `passes/unhook.c` for the
  pattern.
- Return nonzero to abort. There is no partial load: the caller wipes the
  instance and returns.

The DLL host build (`make dll INSTANCE=instance.bin`) ships no passes
by default: repointing LDR entries or touching loader state inside a foreign
host is the operator's explicit choice
(`make dll DLL_PASSES="passes/foo.c ..." INSTANCE=instance.bin`).
