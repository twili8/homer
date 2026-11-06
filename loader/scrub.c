//===- scrub.c - erase imported API names from a mapped image -------------===//
//
// After the loader binds a module's imports, the hint/name and DLL-name
// strings in the mapped copy are dead weight that a memory scanner can read.
// This zeroes them in place. Directory RVAs stay intact; the file on disk is
// untouched.
//
// Scope: the mapped image only, bounded by SizeOfImage. A malformed or
// relocated name pointer cannot walk past the mapping.

#include "loader.h"

// Zero one NUL-terminated ANSI string, bounded by the image and by a hard cap.
static VOID wipe_string(PCHAR base, ULONG size, PCHAR s) {
  ULONG_PTR offset;
  ULONG i;

  if (s == NULL) return;
  offset = (ULONG_PTR)s - (ULONG_PTR)base;
  if (offset >= size) return;

  for (i = 0; i < 256 && offset + i < size; i++) {
    CHAR c = s[i];
    s[i] = 0;
    if (c == 0) return;
  }
}

// Walk one import descriptor table. `nameOff` is the descriptor's DLL-name
// field offset and `thunkOff` its OriginalFirstThunk offset, so normal and
// delay imports share the walk.
static VOID wipe_descriptor_table(PCHAR base, ULONG size, PVOID table,
                                  ULONG descriptorSize, ULONG nameOff,
                                  ULONG thunkOff) {
  ULONG index = 0;

  for (;;) {
    PCHAR   dll;
    PBYTE   desc = (PBYTE)table + index * descriptorSize;
    ULONG   nameRva, thunkRva;
    PIMAGE_THUNK_DATA thunk;
    ULONG   t;

    nameRva  = *(ULONG *)(desc + nameOff);
    if (nameRva == 0 || nameRva >= size) return;

    dll = RVA2VA(PCHAR, base, nameRva);
    wipe_string(base, size, dll);

    thunkRva = *(ULONG *)(desc + thunkOff);
    if (thunkRva == 0 || thunkRva >= size) {
      index++;
      continue;
    }

    thunk = RVA2VA(PIMAGE_THUNK_DATA, base, thunkRva);
    // Bound the thunk walk by the image, not by trust in the table.
    for (t = 0; (ULONG_PTR)(thunk + t) - (ULONG_PTR)base < size; t++) {
      ULONG_PTR data = thunk[t].u1.AddressOfData;
      PIMAGE_IMPORT_BY_NAME ibn;

      if (data == 0) break;
      if (IMAGE_SNAP_BY_ORDINAL(data)) continue;
      if (data >= size) break;
      ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, base, data);
      wipe_string(base, size, (PCHAR)ibn->Name);
    }
    index++;
  }
}

VOID ScrubImportNames(PCHAR base, PIMAGE_NT_HEADERS nt) {
#if HOMER_SCRUB_IMPORTS
  ULONG size, rva;

  if (base == NULL || nt == NULL) return;
  size = nt->OptionalHeader.SizeOfImage;

  if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
              .VirtualAddress;
    if (rva != 0 && rva < size)
      wipe_descriptor_table(base, size, RVA2VA(PVOID, base, rva),
                            sizeof(IMAGE_IMPORT_DESCRIPTOR),
                            offsetof(IMAGE_IMPORT_DESCRIPTOR, Name),
                            offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk));
  }

  if (nt->OptionalHeader.NumberOfRvaAndSizes >
      IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
              .VirtualAddress;
    if (rva != 0 && rva < size)
      wipe_descriptor_table(base, size, RVA2VA(PVOID, base, rva),
                            sizeof(IMAGE_DELAYLOAD_DESCRIPTOR),
                            offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, DllNameRVA),
                            offsetof(IMAGE_DELAYLOAD_DESCRIPTOR,
                                     ImportNameTableRVA));
  }
#else
  (void)base;
  (void)nt;
#endif
}
