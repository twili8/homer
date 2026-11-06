//===- ldrentry.c - present a mapped payload as a loaded module -----------===//
//
// A manually mapped image is otherwise invisible: it has no PEB entry, so
// EnumProcessModules, GetModuleFileName, PEB walkers and most scanners report
// the process as never having loaded it. This registers a well-formed
// LDR_DATA_TABLE_ENTRY in the two lists a legitimate load uses.
//
// Not done, because both need ntdll internals that are not exported and would
// break across Windows builds:
//   - LdrpHashTable (name lookups: GetModuleHandle)
//   - LdrpModuleBaseAddressIndex / LdrpMappingInfoIndex (address lookups)
// Name lookups therefore still miss; list walkers do not.
//
// The entry is unlinked and freed before the image is unmapped, so no list
// walk ever meets a dangling node at shutdown.

#ifndef HOMER_LDRENTRY_C
#define HOMER_LDRENTRY_C

// Real LDR_DATA_TABLE_ENTRY is ~0x120 bytes on x64. The struct in peb.h stops
// at BaseDllName, so this one carries the fields we set plus padding to the
// full size: ntdll reading past them sees zeroes, not the next allocation.
// Offsets come from the field order, so the same definition is correct on x86.
typedef struct _HOMER_LDR_ENTRY {
  LIST_ENTRY     InLoadOrderLinks;
  LIST_ENTRY     InMemoryOrderLinks;
  LIST_ENTRY     InInitializationOrderLinks;
  PVOID          DllBase;
  PVOID          EntryPoint;
  ULONG          SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG          Flags;
  USHORT         LoadCount;
  USHORT         TlsIndex;
  BYTE           Reserved[0x140 - 0x70];
} HOMER_LDR_ENTRY, *PHOMER_LDR_ENTRY;

#define LDR_ENTRY_INSERTED 0x00004000  // LDRP_ENTRY_INSERTED
#define LDR_IMAGE_DLL      0x00000004  // LDRP_IMAGE_DLL

// Append a node before the list head, matching LdrpInsertDataTableEntry.
static VOID link_tail(PLIST_ENTRY head, PLIST_ENTRY node) {
  node->Blink        = head->Blink;
  node->Flink        = head;
  head->Blink->Flink = node;
  head->Blink        = node;
}

static VOID unlink_node(PLIST_ENTRY node) {
  if (node->Flink != NULL && node->Blink != NULL) {
    node->Flink->Blink = node->Blink;
    node->Blink->Flink = node->Flink;
  }
  node->Flink = node;
  node->Blink = node;
}

// ASCII to UNICODE_STRING over a caller-supplied buffer, bounded by cap chars.
static VOID ascii_to_unicode(PUNICODE_STRING out, PWCHAR buffer, const char *text,
                             int cap) {
  int i = 0;
  while (text[i] != 0 && i < cap - 1) {
    buffer[i] = (WCHAR)(unsigned char)text[i];
    i++;
  }
  buffer[i]        = 0;
  out->Length        = (USHORT)(i * sizeof(WCHAR));
  out->MaximumLength = (USHORT)((i + 1) * sizeof(WCHAR));
  out->Buffer        = buffer;
}

// Export-directory name when the image has a sane one, else a plausible
// default. The export name is what a real load would report for a DLL.
static VOID module_name(PVOID base, PIMAGE_NT_HEADERS nt, PDONUT_MODULE mod,
                        char *out) {
  PIMAGE_EXPORT_DIRECTORY exp;
  ULONG size = nt->OptionalHeader.SizeOfImage;
  DWORD rva;

  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .VirtualAddress;
    if (rva != 0 && rva < size) {
      exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
      // The name has to live inside the image, or a malformed header makes
      // this walk off the end of the mapping.
      if (exp->Name != 0 && exp->Name < size) {
        const char *name = RVA2VA(const char *, base, exp->Name);
        DWORD left = size - exp->Name;
        int i = 0;
        while (i < DONUT_MAX_NAME - 1 && (DWORD)i < left && name[i] != 0) {
          out[i] = name[i];
          i++;
        }
        out[i] = 0;
        if (i > 0) return;
      }
    }
  }

  {
    const char *fallback = (mod->type == DONUT_MODULE_DLL) ? "payload.dll"
                                                           : "payload.exe";
    int i = 0;
    while (fallback[i] != 0 && i < DONUT_MAX_NAME - 1) {
      out[i] = fallback[i];
      i++;
    }
    out[i] = 0;
  }
}

// Loader lock around PEB list mutation, so a concurrent module enumeration
// never sees a half-linked node. Returns TRUE when a cookie must be released.
static BOOL lock_loader(PDONUT_INSTANCE inst, ULONG_PTR *cookie) {
  typedef NTSTATUS (NTAPI *lock_t)(ULONG, PULONG, PULONG_PTR);
  ULONG disposition = 0;
  LPVOID ntbase;
  lock_t lock;

  ntbase = xGetLibAddress(inst, "ntdll.dll");
  if (ntbase == NULL) return FALSE;
  lock = (lock_t)xGetProcAddress(inst, ntbase, "LdrLockLoaderLock", 0);
  if (lock == NULL) return FALSE;
  return lock(0, &disposition, cookie) >= 0;
}

static VOID unlock_loader(PDONUT_INSTANCE inst, ULONG_PTR cookie) {
  typedef NTSTATUS (NTAPI *unlock_t)(ULONG, ULONG_PTR);
  LPVOID ntbase;
  unlock_t unlock;

  ntbase = xGetLibAddress(inst, "ntdll.dll");
  if (ntbase == NULL) return;
  unlock = (unlock_t)xGetProcAddress(inst, ntbase, "LdrUnlockLoaderLock", 0);
  if (unlock != NULL) unlock(0, cookie);
}

// Build and link the entry. Returns NULL on failure; registration is
// presentation, never correctness, so the load continues either way.
PHOMER_LDR_ENTRY RegisterModuleEntry(PDONUT_INSTANCE inst, PVOID base,
                                     PIMAGE_NT_HEADERS nt, PDONUT_MODULE mod) {
  PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
  PHOMER_LDR_ENTRY entry;
  UNICODE_STRING baseName, fullName;
  PWCHAR baseBuf, fullBuf;
  ULONG_PTR cookie = 0;
  BOOL locked;
  char name[DONUT_MAX_NAME];
  SIZE_T size = sizeof(HOMER_LDR_ENTRY) + 2 * (DONUT_MAX_NAME * sizeof(WCHAR));

  if (inst == NULL || base == NULL || nt == NULL || peb == NULL ||
      peb->Ldr == NULL)
    return NULL;

  entry = NULL;
  if (inst->api.NtAllocateVirtualMemory((HANDLE)-1, (PVOID *)&entry, 0, &size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE) != 0 ||
      entry == NULL)
    return NULL;
  Memset(entry, 0, size);

  baseBuf = (PWCHAR)((PBYTE)entry + sizeof(HOMER_LDR_ENTRY));
  fullBuf = baseBuf + DONUT_MAX_NAME;

  module_name(base, nt, mod, name);
  ascii_to_unicode(&baseName, baseBuf, name, DONUT_MAX_NAME);
  ascii_to_unicode(&fullName, fullBuf, name, DONUT_MAX_NAME);

  entry->DllBase     = base;
  entry->EntryPoint  = RVA2VA(PVOID, base,
                              nt->OptionalHeader.AddressOfEntryPoint);
  entry->SizeOfImage = nt->OptionalHeader.SizeOfImage;
  entry->BaseDllName = baseName;
  entry->FullDllName = fullName;
  // Inserted but attach-not-called: ntdll only runs DllMain(DETACH) for
  // entries carrying LDRP_PROCESS_ATTACH_CALLED, and this one is unlinked
  // before the image goes away.
  entry->Flags     = LDR_ENTRY_INSERTED;
  if (mod->type == DONUT_MODULE_DLL) entry->Flags |= LDR_IMAGE_DLL;
  entry->LoadCount = 1;

  unlink_node(&entry->InLoadOrderLinks);
  unlink_node(&entry->InMemoryOrderLinks);
  unlink_node(&entry->InInitializationOrderLinks);

  locked = lock_loader(inst, &cookie);
  link_tail(&peb->Ldr->InLoadOrderModuleList, &entry->InLoadOrderLinks);
  link_tail(&peb->Ldr->InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
  if (locked) unlock_loader(inst, cookie);

  DPRINT("ldrentry: registered %s at %p size 0x%X", name, base,
         (unsigned)nt->OptionalHeader.SizeOfImage);
  return entry;
}

// Unlink and free. Safe with NULL.
VOID UnregisterModuleEntry(PDONUT_INSTANCE inst, PHOMER_LDR_ENTRY entry) {
  ULONG_PTR cookie = 0;
  BOOL locked;
  SIZE_T size = 0;

  if (inst == NULL || entry == NULL) return;

  locked = lock_loader(inst, &cookie);
  unlink_node(&entry->InLoadOrderLinks);
  unlink_node(&entry->InMemoryOrderLinks);
  unlink_node(&entry->InInitializationOrderLinks);
  if (locked) unlock_loader(inst, cookie);

  inst->api.NtFreeVirtualMemory((HANDLE)-1, (PVOID *)&entry, &size, MEM_RELEASE);
  DPRINT("ldrentry: unregistered");
}

#endif // HOMER_LDRENTRY_C
