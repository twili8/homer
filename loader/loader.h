/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef LOADER_H
#define LOADER_H

#if !defined(_MSC_VER)
#define __out_ecount_full(x)
#define __out_ecount_full_opt(x)
#include <inttypes.h>
#endif

#include <windows.h>
#include <wincrypt.h>
#include <oleauto.h>
#include <objbase.h>
#include <wininet.h>
#include <shlwapi.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#if defined(dbg)
#include <stdio.h>
#include <string.h>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

 #define DPRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILENAME__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#define STATIC_KEY ((__TIME__[7] - '0') * 1    + (__TIME__[6] - '0') * 10  + \
                    (__TIME__[4] - '0') * 60   + (__TIME__[3] - '0') * 600 + \
                    (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

// Erase import hint/name and DLL-name strings from a mapped image.
VOID ScrubImportNames(PCHAR base, PIMAGE_NT_HEADERS nt);

// 0 disables PEB registration (the mapped image stays invisible to module
// lists). Presentation only; the load does not depend on it.
#ifndef HOMER_REGISTER_MODULE
#define HOMER_REGISTER_MODULE 1
#endif

// Erase imported API names from the mapped payload after imports are bound.
// Memory-only; the image on disk is untouched. Set to 0 to keep the names
// for debugging (they show up in a memory scan otherwise).
#ifndef HOMER_SCRUB_IMPORTS
#define HOMER_SCRUB_IMPORTS 1
#endif

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#if defined(_M_IX86) || defined(__i386__)
// return pointer to code in memory
char *get_pc(void);

// PC-relative addressing for x86 code. Similar to RVA2VA except using functions in payload
#define ADR(type, addr) (type)(get_pc() - ((ULONG_PTR)&get_pc - (ULONG_PTR)addr))
#else
#define ADR(type, addr) (type)(addr) // do nothing on 64-bit
#endif

void *Memset(void *ptr, int value, unsigned int num);
void *Memcpy(void *destination, const void *source, unsigned int num);
int Memcmp(const void *ptr1, const void *ptr2, unsigned int num);
int _strcmp(const char *s1, const char *s2);

#if !defined(_MSC_VER)
#define memcmp(x,y,z) Memcmp(x,y,z)
#endif

#include "peb.h"           // Process Environment Block
#include "winapi.h"        // Prototypes

#include "donut.h"

    // In-Memory execution of unmanaged native code. YMMV with EXE files requiring subsystem.
    VOID RunPE(PDONUT_INSTANCE, PDONUT_MODULE);

    // Execute a raw shellcode payload.
    VOID RunShellcode(PDONUT_INSTANCE, PDONUT_MODULE);
    
    LPVOID xGetProcAddressByHash(PDONUT_INSTANCE, ULONGLONG, ULONGLONG);

    LPVOID xGetProcAddressByHash(PDONUT_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV);

    // Present a mapped payload as a loaded module (PEB list entry).
    struct _HOMER_LDR_ENTRY;
    struct _HOMER_LDR_ENTRY *RegisterModuleEntry(PDONUT_INSTANCE, PVOID,
                                                 PIMAGE_NT_HEADERS,
                                                 PDONUT_MODULE);
    VOID UnregisterModuleEntry(PDONUT_INSTANCE, struct _HOMER_LDR_ENTRY *);

    LPVOID xGetLibAddress(PDONUT_INSTANCE inst, PCHAR dll_name);

    // PEB module/export resolver (peb.c), shared by the core and passes.
    // Callers stack-build names so no string lands in .rdata.
    LPVOID homer_get_proc(const char *dll, const char *fn);
    HMODULE homer_find_module(const char *name);
    int homer_streq(const char *a, const char *b);

    LPVOID xGetProcAddress(PDONUT_INSTANCE inst, LPVOID base, PCHAR api_name, DWORD ordinal);

// Operator passes (loader/pass.h). Included last: it needs DONUT_INSTANCE
// and DONUT_MODULE from donut.h above.
#include "pass.h"

#endif
