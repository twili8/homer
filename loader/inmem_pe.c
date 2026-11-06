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

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef VOID  (WINAPI *Start_t)(PPEB);
typedef VOID  (WINAPI *DllParam_t)(PVOID);
typedef VOID  (WINAPI *DllVoid_t)(VOID);

typedef CHAR**  (WINAPI *p_acmdln_t)(VOID);
typedef WCHAR** (WINAPI *p_wcmdln_t)(VOID);

BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR NewCommandLine);
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name);
BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host);

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst, PDONUT_MODULE mod) {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost, ntnew;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_SECTION_HEADER       shcp = NULL;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    IMAGE_NT_HEADERS            ntc;
    PHOMER_LDR_ENTRY            ldrEntry = NULL;
    DWORD                       rva, size;
    PDWORD                      adr;
    PDWORD                      sym;
    PWORD                       ord;
    PBYTE                       ofs;
    PCHAR                       str, name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    DllMain_t                   DllMain;            // DLL
    Start_t                     Start;              // EXE
    DllParam_t                  DllParam = NULL;    // DLL function accepting one string parameter
    DllVoid_t                   DllVoid  = NULL;    // DLL function that takes no arguments
    LPVOID                      base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[DONUT_MAX_NAME+1];
    DWORD                       size_of_img;
    PVOID                       baseAddress;
    SIZE_T                      numBytes;
    DWORD                       newprot;
    NTSTATUS                    status;
    HANDLE                      hSection;
    LARGE_INTEGER               liSectionSize;
    PVOID                       cs = NULL;
    SIZE_T                      viewSize = 0;
    BOOL                        has_reloc;
    
    base = mod->data;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    
    host    = inst->api.GetModuleHandleA(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost  = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);
    
    if (nt->FileHeader.Machine != nthost->FileHeader.Machine) {
      // This is not always the case:
      // If IL_ONLY PE32 is loaded on 64-bit Windows and we load a PE32+ exe/dll
		  if ((nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && nthost->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
			  && !CheckForILOnly(nthost, (ULONG_PTR)host)) {
			  DPRINT("Host process %08lx and file %08lx are not compatible...cannot load.",
				nthost->FileHeader.Machine, nt->FileHeader.Machine);
			  return;
		  }
	  }
    
    DPRINT("section size %" PRIi32 " bytes", nt->OptionalHeader.SizeOfImage);
    
    liSectionSize.QuadPart = nt->OptionalHeader.SizeOfImage;

    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0? FALSE : TRUE;
    if (!has_reloc)
    {
      DPRINT("No relocation information present, setting the base to: 0x%p", (PVOID)nt->OptionalHeader.ImageBase);
      cs = (PVOID)nt->OptionalHeader.ImageBase;
    }

    status = inst->api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &liSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    DPRINT("NTSTATUS: %d", status);
    if(status != 0) return;
    
    status = inst->api.NtMapViewOfSection(hSection, (HANDLE)-1, &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

    ntnew = RVA2VA(PIMAGE_NT_HEADERS, cs, dos->e_lfanew);

    DPRINT("NTSTATUS: %d", status);
    if(status != 0 && status != 0x40000003) return;

    
    if(cs == NULL) return;


    Memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);


    ntnew->OptionalHeader.ImageBase = (ULONGLONG)(uintptr_t)cs;

    sh = IMAGE_FIRST_SECTION(ntnew);
      
    for(i=0; i<ntnew->FileHeader.NumberOfSections; i++) {
      PBYTE dest = (PBYTE)cs + sh[i].VirtualAddress;
      PBYTE source = (PBYTE)base + sh[i].PointerToRawData;

      if (sh[i].SizeOfRawData == 0)
        DPRINT("Section is empty of data, but may contain uninitialized data.");
      
      Memcpy(dest,
          source,
          sh[i].SizeOfRawData);
      
      sh[i].Misc.PhysicalAddress = (DWORD)*dest;

      DPRINT("%.8s copied: src 0x%X dst 0x%X @ %p size 0x%X", sh[i].Name,
             sh[i].VirtualAddress, sh[i].PointerToRawData, dest,
             sh[i].SizeOfRawData);
    }
    

    ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;
    DPRINT("Image Relocation Offset: 0x%p", ofs);

    if (has_reloc && ofs != 0) {
        
      rva  = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      
      while ((PBYTE)ibr < ((PBYTE)cs + rva + size) && ibr->SizeOfBlock != 0) {
        list = (PIMAGE_RELOC)(ibr + 1);
  
        while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
          // check that the RVA is within the boundaries of the PE
          if (ibr->VirtualAddress + list->offset < ntnew->OptionalHeader.SizeOfImage) {
            PULONG_PTR address = (PULONG_PTR)((PBYTE)cs + ibr->VirtualAddress + list->offset);
            if (list->type == IMAGE_REL_BASED_DIR64) {
              *address += (ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
              *address += (DWORD)(ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGH) {
              *address += HIWORD(ofs);
            } else if (list->type == IMAGE_REL_BASED_LOW) {
              *address += LOWORD(ofs);
            } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
              DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
              goto pe_cleanup;
            }
          }
          list++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)list;
      }
    }
    
    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing the Import Table");
      
      imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);
        
        for (;imp->Name!=0; imp++) {
        name = RVA2VA(PCHAR, cs, imp->Name);
        
        dll = xGetLibAddress(inst, name);
        
          oft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);
          
        for (;; oft++, ft++) {
          if (oft->u1.AddressOfData == 0) break;
          
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

            if(mod->thread != 0) {
              // ExitProcess would kill the host; die as this thread instead.
              if(IsExitAPI(inst, ibn->Name)) {
                DPRINT("Replacing %s!%s with ntdll!RtlExitUserThread", name, ibn->Name);
                ft->u1.Function = (ULONG_PTR)inst->api.RtlExitUserThread;
                continue;
              }
            }
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          }
        }
      }
    }
    
    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing Delayed Import Table");
      
      del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);
      
      for (;del->DllNameRVA != 0; del++) {
        name = RVA2VA(PCHAR, cs, del->DllNameRVA);
        
        dll = xGetLibAddress(inst, name);
        
        if(dll == NULL) continue;
        
        // Resolve the API for this library
        oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);
          
        for (;; oft++, ft++) {
          if (oft->u1.AddressOfData == 0) break;

          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          }
        }
      }
    }
      
    size_of_img = ntnew->OptionalHeader.SizeOfImage;
    Start = RVA2VA(Start_t, cs, ntnew->OptionalHeader.AddressOfEntryPoint);

    // Snapshot headers; the mapped copy is wiped below.
    ntc = *nt;

    shcp = NULL;
    {
      PVOID _base = NULL; SIZE_T _sz = ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
      inst->api.NtAllocateVirtualMemory((HANDLE)-1, &_base, 0, &_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      shcp = _base;
    }

    Memcpy(shcp, sh, ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    /* Operator passes run after the image is bound, while it is still
     * writable, before headers are wiped and protections are set. The stock
     * scrub pass runs here. A nonzero return aborts the load. */
    if (homer_run_passes(HOMER_PRE_JUMP, inst, mod, cs, ntnew) != 0) goto pe_cleanup;

    if(inst->headers == 1)
    {
        Memset(cs,   0, nt->OptionalHeader.SizeOfHeaders);
      Memset(base, 0, nt->OptionalHeader.SizeOfHeaders);
    }

    status = inst->api.NtUnmapViewOfSection((HANDLE)-1, cs);
    DPRINT("NTSTATUS: %d", status);
    if(status != 0) return;

    // Done writing the RW view; drop it so the executable view below starts clean.
    if (has_reloc) {
      cs = NULL;
    }
    viewSize = 0;

    status = inst->api.NtMapViewOfSection(hSection, (HANDLE)-1, &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);
    DPRINT("View size: %lld", viewSize);
    DPRINT("NTSTATUS: %d", status);
    if(status != 0) return;

    DPRINT("Mapped to address: %p", cs);

    // Pre-mark everything WC: padding between sections must not stay RWX.
    PVOID _vp_base = cs; SIZE_T _vp_size = viewSize; ULONG _vp_old = 0;
    inst->api.NtProtectVirtualMemory((HANDLE)-1, &_vp_base, &_vp_size, PAGE_WRITECOPY, &_vp_old);
    cs = _vp_base; viewSize = _vp_size;

    DPRINT("Setting permissions for each PE section");
    // done with binary manipulation, mark section permissions appropriately
    for (i = 0; i < ntc.FileHeader.NumberOfSections; i++)
    {
      BOOL isRead = (shcp[i].Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
      BOOL isWrite = (shcp[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
      BOOL isExecute = (shcp[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

      if (isWrite & isExecute)
        continue; // do nothing, already WCX
      else if (isRead & isExecute)
          newprot = PAGE_EXECUTE_READ;
      else if (isRead & isWrite & !isExecute)
      {
        newprot = PAGE_WRITECOPY; // must use WC because RW is incompatible with permissions of initial view (WCX)
      }
      else if (!isRead & !isWrite & isExecute)
          newprot = PAGE_EXECUTE;
      else if (isRead & !isWrite & !isExecute)
          newprot = PAGE_READONLY;

      baseAddress = (PBYTE)cs + shcp[i].VirtualAddress;

      if (i < (ntc.FileHeader.NumberOfSections - 1))
        numBytes = ((PBYTE)cs + shcp[i+1].VirtualAddress) - ((PBYTE)cs + shcp[i].VirtualAddress);
      else
        numBytes = shcp[i].SizeOfRawData;

      DPRINT("%.8s @ %p size 0x%llX prot 0x%X", shcp[i].Name, baseAddress, numBytes, newprot);
      
      PVOID _vp_base = baseAddress; SIZE_T _vp_size = numBytes; ULONG _vp_old = 0;
      if (inst->api.NtProtectVirtualMemory((HANDLE)-1, &_vp_base, &_vp_size, newprot, &_vp_old) != 0) _vp_old = 0;
      baseAddress = _vp_base; numBytes = _vp_size;
        DPRINT("VirtualProtect failed");
    }

    DPRINT("Setting permissions of module headers to READONLY (%d bytes)", ntc.OptionalHeader.BaseOfCode);
    PVOID _hdr_base = cs; SIZE_T _hdr_size = ntc.OptionalHeader.BaseOfCode; ULONG _hdr_old = 0;
    inst->api.NtProtectVirtualMemory((HANDLE)-1, &_hdr_base, &_hdr_size, PAGE_READONLY, &_hdr_old);
    cs = _hdr_base;

#if HOMER_REGISTER_MODULE
    // Present the image as a loaded module so module lists show it.
    ldrEntry = RegisterModuleEntry(inst, cs, ntnew, mod);
#endif

    /** 
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(rva != 0) {
      DPRINT("Processing TLS directory");
      
      tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);
      
      // address of callbacks is absolute. requires relocation information
      callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
      DPRINT("AddressOfCallBacks : %p", callbacks);
      
      // DebugBreak();
      
      if(callbacks) {
        while(*callbacks != NULL) {
          // call function
          DPRINT("Calling %p", *callbacks);
          (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
          callbacks++;
        }
      }
    }

    if(mod->type == DONUT_MODULE_DLL) {
      DllMain = RVA2VA(DllMain_t, cs, ntc.OptionalHeader.AddressOfEntryPoint);
      DPRINT("Executing entrypoint of DLL: %p", (PVOID)DllMain);
      DPRINT("HINSTANCE: %p\n\n", (PVOID)cs);
      DllMain(cs, DLL_PROCESS_ATTACH, NULL);
      
      if(mod->method[0] != 0) {
        DPRINT("Resolving address of %s", (char*)mod->method);
        
        rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, cs, rva);
        
        if(rva != 0) {
          cnt = exp->NumberOfNames;
          
          DPRINT("IMAGE_EXPORT_DIRECTORY.NumberOfNames : %i", cnt);
          
          if(cnt != 0) {
            adr = RVA2VA(PDWORD,cs, exp->AddressOfFunctions);
            sym = RVA2VA(PDWORD,cs, exp->AddressOfNames);
            ord = RVA2VA(PWORD, cs, exp->AddressOfNameOrdinals);

            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfFunctions : 0x%X", *adr);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNames : 0x%X", *sym);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals : 0x%X", *ord);
        
            do {
              str = RVA2VA(PCHAR, cs, sym[cnt-1]);
              if(!_strcmp(str, mod->method)) {
                DllParam = RVA2VA(DllParam_t, cs, adr[ord[cnt-1]]);
                break;
              }
            } while (--cnt);
      
            if(DllParam != NULL) {
              DPRINT("Invoking %s", mod->method);
              if(mod->args[0] != 0) {
                if(mod->unicode) {
                  ansi2unicode(inst, mod->args, buf);
                }
                DllParam((mod->unicode) ? (PVOID)buf : (PVOID)mod->args);
              } else {
                DllVoid = (DllVoid_t)DllParam;
                DllVoid();
              }
            } else {
              DPRINT("Unable to resolve API");
              goto pe_cleanup;
            }
          }
        }
      }
    } else {

      if(mod->args[0] != 0) {
        ansi2unicode(inst, mod->args, buf);
        DPRINT("Setting command line: %ws", buf);
        SetCommandLineW(inst, buf);
      }

      if(mod->thread != 0) {
        // Exit-related IAT entries point at RtlExitUserThread, so the thread
        // dies back here instead of killing the host (unless resolved dynamically).
        DPRINT("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
        HANDLE _ht = NULL; NTSTATUS _ns;
        _ns = inst->api.NtCreateThreadEx(&_ht, 0x1FFFFF, NULL, (HANDLE)-1, (PVOID)Start, NULL, 0, 0, 0, 0, NULL);
        hThread = _ns == 0 ? _ht : NULL;
        
        if(hThread != NULL) {
          inst->api.NtWaitForSingleObject(hThread, FALSE, NULL); // NULL timeout waits forever
          DPRINT("Process terminated");
        }
      } else {
        DPRINT("Executing entrypoint: %p", (PVOID)Start);
        Start(NtCurrentTeb()->ProcessEnvironmentBlock);
      }
    }

    // Block forever instead of exiting, on request.
    if (inst->exit_opt == DONUT_OPT_EXIT_BLOCK) {
      DPRINT("Execution complete. Blocking indefintely.");
      for(;;) { __asm__ volatile("pause"); }
    }

pe_cleanup:
    if(cs != NULL) {
      DPRINT("Releasing memory");

      PVOID _base = shcp; SIZE_T _sz = 0;
      inst->api.NtFreeVirtualMemory((HANDLE)-1, &_base, &_sz, MEM_RELEASE);
      
      // Unlink before unmapping so no list walk touches a dangling node.
      UnregisterModuleEntry(inst, ldrEntry);
      ldrEntry = NULL;

      inst->api.NtUnmapViewOfSection((HANDLE)-1, cs);
      inst->api.NtClose(hSection);
    }

    DPRINT("Wiping payload from Donut module in memory.");
    Memset(base, 0, mod->len);
}

// True when `name` is an exit API (IAT slot gets RtlExitUserThread).
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name) {
    PCHAR str;
    CHAR  api[128];
    INT   i;
    
    str = inst->exit_api;
    
    for(;;) {
      // Semicolon-separated list walk; matches MainProc's dll_names loop.
      for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) api[i] = str[i];
      if(i == 0) break;
      str += (i + 1);
      api[i] = '\0';
      if(!_strcmp(api, name)) return TRUE;
    } 
    return FALSE;
}

// True when `ptr` is our own RW heap allocation.
BOOL IsHeapPtr(PDONUT_INSTANCE inst, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    SIZE_T _retlen = 0;
    res = inst->api.NtQueryVirtualMemory((HANDLE)-1, ptr, 0, &mbi, sizeof(mbi), &_retlen);
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host)
{
	PIMAGE_DATA_DIRECTORY		net_data_dir;
	PBYTE						cor20_hdr;
	DWORD						cor20_flags;

	net_data_dir = &nthost->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	if (net_data_dir->Size && net_data_dir->VirtualAddress) {

		cor20_hdr = (PBYTE)(host + net_data_dir->VirtualAddress);
		cor20_flags = *(PDWORD)((ULONG_PTR)cor20_hdr + 0x10);

		if (cor20_flags & 0x1 /* IL_ONLY */) {
			if ((cor20_flags & 0x2) /* ! 32_BIT_REQUIRED */ == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// Rewrite the host PEB command line in place. kernelbase reads these globals at
// process init; only tested on Windows 10, expected to work back to 7.
BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR CommandLine) {
    PIMAGE_DOS_HEADER            dos;
    PIMAGE_NT_HEADERS            nt;
    PIMAGE_SECTION_HEADER        sh;
    DWORD                        i, cnt;
    PULONG_PTR                   ds;
    HMODULE                      m;
    ANSI_STRING                  ansi;
    PANSI_STRING                 mbs;
    PUNICODE_STRING              wcs;
    PPEB                         peb;
    PPEB_LDR_DATA                ldr;
    PLDR_DATA_TABLE_ENTRY        dte;
    PRTL_USER_PROCESS_PARAMETERS upp;
    BOOL                         bSet = FALSE;
    CHAR                         **argv;
    WCHAR                        **wargv;
    p_acmdln_t                   p_acmdln;
    p_wcmdln_t                   p_wcmdln;
    CHAR                         sym[128];
    PCHAR                        str;
    INT                          fptr, atype;
    PVOID                        addr, wcmd, acmd;
    
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    upp = peb->ProcessParameters;

    DPRINT("Obtaining handle for %s", inst->kernelbase);
    m   = inst->api.GetModuleHandleA(inst->kernelbase);
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // Find .data for the pointer table.
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)inst->dataname) {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    
    DPRINT("Searching %i pointers", cnt);
    
    wcmd = (PVOID)upp->CommandLine.Buffer;
    
    for(i=0; i<cnt; i++) {
      wcs = (PUNICODE_STRING)&ds[i];
      // skip if not equal
      if(wcs->Buffer != wcmd) continue;
      DPRINT("BaseUnicodeCommandLine found at %p:%p : %ws", &ds[i], wcs->Buffer, wcs->Buffer);
      // overwrite buffer for GetCommandLineW (custom, no RtlCreateUnicodeString)
      {
        ULONG _wlen = 0;
        while (CommandLine[_wlen]) _wlen++;
        _wlen++; // include null
        wcs->Buffer = (PWSTR)inst->api.RtlAllocateHeap(((HANDLE)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap), 0, _wlen * sizeof(WCHAR));
        wcs->Length = (USHORT)((_wlen - 1) * sizeof(WCHAR));
        wcs->MaximumLength = (USHORT)(_wlen * sizeof(WCHAR));
        for (ULONG _k = 0; _k < _wlen; _k++) wcs->Buffer[_k] = CommandLine[_k];
      }
      DPRINT("GetCommandLineW() : %ws", GetCommandLineW());
      break;
    }
    
    acmd = (PVOID)upp->CommandLine.Buffer;
    
    for(i=0; i<cnt; i++) {
      mbs = (PANSI_STRING)&ds[i];
      // skip if not equal
      if(mbs->Buffer != acmd) continue;
      DPRINT("BaseAnsiCommandLine found at %p:%p : %s", &ds[i], mbs->Buffer, mbs->Buffer);
      // custom ANSI conversion (no RtlUnicodeStringToAnsiString)
      {
        ULONG _wlen = wcs->Length / sizeof(WCHAR);
        if (_wlen == 0) _wlen = 1;
        mbs->Buffer = (PCHAR)inst->api.RtlAllocateHeap(((HANDLE)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap), 0, _wlen);
        mbs->Length = (USHORT)(_wlen - 1);
        mbs->MaximumLength = (USHORT)_wlen;
        for (ULONG _k = 0; _k < _wlen - 1; _k++) mbs->Buffer[_k] = (CHAR)(wcs->Buffer[_k] & 0xFF);
        mbs->Buffer[_wlen - 1] = 0;
      }
      Memcpy(&ds[i], mbs, sizeof(ANSI_STRING));
      DPRINT("GetCommandLineA() : %s", GetCommandLineA());
      break;
    }
    
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // check for exported symbols and patch according to string type
      str = (PCHAR)inst->cmd_syms;
      
      for(;;) {
        // reset flags
        atype = 1; fptr = 0;
        for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) {
          // w indicates unicode type
          if(str[i] == 'w') atype = 0;
          // p indicates function pointer
          if(str[i] == 'p') fptr  = 1;
          sym[i] = str[i];
        }
        if(i == 0) break;
        str += (i + 1);
        sym[i] = '\0';
        addr = xGetProcAddress(inst, dte->DllBase, sym, 0);
        if(addr == NULL) continue;
        if(atype) {
          argv = (PCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_acmdln = (p_acmdln_t)addr;
            argv = p_acmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(argv != NULL && IsHeapPtr(inst, *argv)) {
            DPRINT("Setting %ws!%s \"%s\" to \"%s\"", 
              dte->BaseDllName.Buffer, sym, *argv, ansi.Buffer);
            *argv = ansi.Buffer;
          }
        } else {
          wargv = (PWCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_wcmdln = (p_wcmdln_t)addr;
            wargv = p_wcmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(wargv != NULL && IsHeapPtr(inst, *wargv)) {
            DPRINT("Setting %ws!%s \"%ws\" to \"%ws\"", 
              dte->BaseDllName.Buffer, sym, *wargv, wcs->Buffer);
            *wargv = wcs->Buffer;
          }
        }
      }
    }
    return TRUE;
}
