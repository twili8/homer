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

// Resolve `api_name` in any loaded DLL except `original_dll`; falls back to LoadLibrary.
LPVOID resolve_forwarded_export(PDONUT_INSTANCE inst, LPVOID original_dll, PCHAR dll_name, PCHAR api_name) {
  PPEB                    peb;
  PPEB_LDR_DATA           ldr;
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PLDR_DATA_TABLE_ENTRY   dte;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL, base;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;

  peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
  ldr = (PPEB_LDR_DATA)peb->Ldr;
  
  for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
       dte->DllBase != NULL && addr == NULL;
       dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
  {
    base = dte->DllBase;
    if (base == original_dll) continue;

    addr = xGetProcAddress(inst, base, api_name, 0);
  }
  if (addr == NULL) {
    HMODULE hModule = xGetLibAddress(inst, dll_name);
    
    if(hModule != NULL) {
      DPRINT("Calling GetProcAddress(%s)", api_name);
      addr = inst->api.GetProcAddress(hModule, api_name);
    } else addr = NULL;
  }
  
  return addr;
}

// Resolve an export by name or ordinal, following forwarder chains.
LPVOID xGetProcAddress(PDONUT_INSTANCE inst, LPVOID base, PCHAR api_name, DWORD ordinal) {
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;
  CHAR                    dll_name[64];
  CHAR                    new_api[64];
  DWORD                   i;
  PCHAR                   p;

  if (base == NULL) return NULL;

  dos = (PIMAGE_DOS_HEADER)base;
  nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
  dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
  rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  
  if (rva==0) return NULL;
  
  exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
  adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
  sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
  ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

  if (api_name != NULL) {
    cnt = exp->NumberOfNames;
    if (cnt==0) return NULL;
  
    do {
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      if (!_strcmp(api, api_name)) {
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
      }
    } while (--cnt && addr == NULL);
  } else {
    addr = RVA2VA(PVOID, base, adr[ordinal  - exp->Base]);
  }

  // Forwarder RVAs point inside the export directory.
  if ((PBYTE)addr >= (PBYTE)exp &&
      (PBYTE)addr <  (PBYTE)exp + 
      dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
  {
      
    p=(char*)addr;
    
    for(i=0; p[i] != 0 && i < sizeof(dll_name)-4; i++) {
      dll_name[i] = p[i];
      if(p[i] == '.') break;
    }

    dll_name[i+1] = 'd';
    dll_name[i+2] = 'l';
    dll_name[i+3] = 'l';
    dll_name[i+4] = 0;
    
    p += i + 1;
    
    for(i=0; p[i] != 0 && i < sizeof(new_api)-1;i++) {
      new_api[i] = p[i];
    }
    new_api[i] = 0;

    addr = resolve_forwarded_export(inst, base, dll_name, new_api);
  }
  return addr;
}

// Find a loaded DLL by name, loading it when missing.
LPVOID xGetLibAddress(PDONUT_INSTANCE inst, PCHAR search) {
    PPEB                    peb;
    PPEB_LDR_DATA           ldr;
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PLDR_DATA_TABLE_ENTRY   dte;
    PIMAGE_EXPORT_DIRECTORY exp;
    LPVOID                  addr = NULL, base;
    DWORD                   rva;
    PCHAR                   name;
    CHAR                    dll_name[64];
    DWORD                   i;
    int                     correct = -1;

    for(i=0; search[i] != 0 && i < 64; i++) {
      dll_name[i] = search[i];
    }
    dll_name[i] = 0;
    if (dll_name[i-4] != '.') {
      dll_name[i++] = '.';
      dll_name[i++] = 'd';
      dll_name[i++] = 'l';
      dll_name[i++] = 'l';
      dll_name[i++] = 0;
    }

    DPRINT("Searching for DLL in PEB: %s", dll_name);

    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      base = dte->DllBase;
      dos  = (PIMAGE_DOS_HEADER)base;
      nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
      rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (rva == 0) continue;

      exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
      name = RVA2VA(PCHAR, base, exp->Name);

      correct = stricmp(dll_name, name);

      if (correct == 0) {
        addr = base;
      }
    }

    DPRINT("Address of DLL: %p", addr);

    if (addr == NULL) {
      addr = inst->api.LoadLibraryA(dll_name);
      DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", dll_name, addr);
    }
    return addr;
}

// Find an export by (name-hash XOR dll-hash), following forwarders.
LPVOID FindExport(PDONUT_INSTANCE inst, LPVOID base, ULONG64 api_hash, ULONG64 iv){
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   i, j, cnt, rva;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll, p;
    LPVOID                  addr=NULL;
    ULONG64                 dll_hash;
    CHAR                    buf[MAX_PATH], dll_name[64], api_name[128];
    
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    if (rva==0) return NULL;
    
    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    cnt = exp->NumberOfNames;
    
    if (cnt==0) return NULL;
    
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2VA(PCHAR, base, exp->Name);
    
    for(i=0;dll[i]!=0;i++) {
      buf[i] = dll[i] | 0x20;
    }
    buf[i] = 0;
    dll_hash = maru(buf, iv);

    do {
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      if ((maru(api, iv) ^ dll_hash) == api_hash) {
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
        
        // Forwarder RVAs point inside the export directory.
        if ((PBYTE)addr >= (PBYTE)exp &&
            (PBYTE)addr <  (PBYTE)exp + 
            dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
        {
            
          p=(char*)addr;
          
          for(i=0; p[i] != 0 && i < sizeof(dll_name)-4; i++) {
            dll_name[i] = p[i];
            if(p[i] == '.') break;
          }

          dll_name[i+1] = 'd';
          dll_name[i+2] = 'l';
          dll_name[i+3] = 'l';
          dll_name[i+4] = 0;
          
          p += i + 1;
          
          for(i=0; p[i] != 0 && i < sizeof(api_name)-1;i++) {
            api_name[i] = p[i];
          }
          api_name[i] = 0;

          addr = resolve_forwarded_export(inst, base, dll_name, api_name);
        }
        return addr;
      }
    } while (--cnt && addr == NULL);
    
    return addr;
}

// Walk every loaded module for a hashed export.
LPVOID xGetProcAddressByHash(PDONUT_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV) {
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                addr = NULL;
     
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && addr == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      addr = FindExport(inst, dte->DllBase, ulHash, ulIV);  
    }
    return addr;
}

/* PEB module/export resolver shared by the loader core and operator
 * passes. Callers stack-build names so no string lands in .rdata for
 * the static extractor. */
LPVOID homer_get_proc(const char *dll, const char *fn);

// --- Homer bootstrap helpers (layers 4/5) ---
int homer_streq(const char *a, const char *b) { while(*a && *b) { if(*a != *b) return 1; a++; b++; } return *a || *b; }

HMODULE homer_find_module(const char *name) {
    PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    for(dte = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
        dte && dte->DllBase; dte = (PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink) {
        PWSTR b = dte->BaseDllName.Buffer;
        uint32_t i = 0, j = 0, ok = 1;
        if(b == NULL) continue;
        while(name[j]) {
            uint16_t c = b[i];
            if(c == 0) { ok = 0; break; }
            uint16_t lc = (c >= 'A' && c <= 'Z') ? (c + ('a'-'A')) : c;
            uint8_t  rn = (uint8_t)name[j];
            uint8_t  ln = (rn >= 'A' && rn <= 'Z') ? (rn + ('a'-'A')) : rn;
            if(lc != ln) { ok = 0; break; }
            i++; j++;
        }
        if(ok && b[i] == 0) return (HMODULE)dte->DllBase;
    }
    return NULL;
}

static LPVOID homer_find_export(HMODULE base, const char *name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD names, funcs;
    PWORD ords;
    DWORD i;
    if(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return NULL;
    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base,
                 nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if(exp->NumberOfNames == 0) return NULL;
    names = RVA2VA(PDWORD, base, exp->AddressOfNames);
    ords  = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    funcs = RVA2VA(PDWORD, base, exp->AddressOfFunctions);
    for(i = 0; i < exp->NumberOfNames; i++) {
        PCHAR n = RVA2VA(PCHAR, base, names[i]);
        if(homer_streq(n, name) == 0) {
            return RVA2VA(LPVOID, base, funcs[ords[i]]);
        }
    }
    return NULL;
}

LPVOID homer_get_proc(const char *dll, const char *fn) {
    char mod[64], func[64];
    char dllbuf[64];
    HMODULE base;
    LPVOID  a;
    int     depth;
    uint32_t i = 0, k;
    while(dll[i] && i < 60) { dllbuf[i] = dll[i]; i++; }
    if(i < 4 || dllbuf[i-4] != '.' || dllbuf[i-3] != 'd' ||
       dllbuf[i-2] != 'l' || dllbuf[i-1] != 'l') {
        dllbuf[i++] = '.'; dllbuf[i++] = 'd'; dllbuf[i++] = 'l'; dllbuf[i++] = 'l';
    }
    dllbuf[i] = 0;

    base = homer_find_module(dllbuf);
    if(base == NULL) return NULL;
    a = homer_find_export(base, fn);
    for(depth = 0; depth < 4 && a != NULL; depth++) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
        DWORD va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if((PBYTE)a < (PBYTE)base + va || (PBYTE)a >= (PBYTE)base + va + sz) break;
        i = 0; k = 0;
        {
            char *p = (char*)a;
            while(p[i] && p[i] != '.' && i < 63) { mod[i] = p[i]; i++; }
            mod[i] = 0;
            if(p[i] != '.') break;
            i++;
            while(p[i] && k < 63) { func[k++] = p[i++]; }
            func[k] = 0;
        }
        {
            uint32_t kk = 0;
            while(mod[kk]) kk++;
            if(kk < 4 || mod[kk-4] != '.' || mod[kk-3] != 'd' ||
               mod[kk-2] != 'l' || mod[kk-1] != 'l') {
                mod[kk++] = '.'; mod[kk++] = 'd'; mod[kk++] = 'l'; mod[kk++] = 'l'; mod[kk] = 0;
            }
        }
        base = homer_find_module(mod);
        if(base == NULL) return NULL;
        a = homer_find_export(base, func);
    }
    return a;
}
