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

#ifndef WINAPI_H
#define WINAPI_H

#include <windows.h>

    typedef LPVOID (WINAPI *RtlAllocateHeap_t)(
      HANDLE hHeap,
      DWORD  dwFlags,
      SIZE_T dwBytes);

    


  
    typedef HMODULE (WINAPI *LoadLibraryA_t)(
      LPCSTR                lpLibFileName);

    typedef FARPROC (WINAPI *GetProcAddress_t)(
      HMODULE               hModule,
      LPCSTR                lpProcName);

    
    typedef BOOL  (WINAPI *NtClose_t)(HANDLE hObject);

      
    typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
        HANDLE                Handle,
        BOOLEAN               Alertable,
        PLARGE_INTEGER        Timeout);

    typedef NTSTATUS (NTAPI *NtQueryVirtualMemory_t)(
      HANDLE                    ProcessHandle,
      PVOID                     BaseAddress,
      int                       MemoryInformationClass,
      PVOID                     MemoryInformation,
      SIZE_T                    MemoryInformationLength,
      PSIZE_T                   ReturnLength);
      
    typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
      HANDLE                    ProcessHandle,
      PVOID *                   BaseAddress,
      PSIZE_T                   RegionSize,
      ULONG                     NewAccessProtection,
      PULONG                    OldAccessProtection);

    typedef HMODULE (WINAPI *GetModuleHandleA_t)(
      LPCSTR                    lpModuleName);

    typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
      HANDLE                ProcessHandle,
      PVOID *               BaseAddress,
      ULONG_PTR             ZeroBits,
      PSIZE_T               RegionSize,
      ULONG                 AllocationType,
      ULONG                 Protect);

    typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
      HANDLE                ProcessHandle,
      PVOID *               BaseAddress,
      PSIZE_T               RegionSize,
      ULONG                 FreeType);

       
      

      

          
    typedef void (WINAPI *RtlExitUserThread_t)(UINT uExitCode);

    typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    
    typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
      PHANDLE                ThreadHandle,
      ACCESS_MASK            DesiredAccess,
      PVOID                  ObjectAttributes,
      HANDLE                 ProcessHandle,
      PVOID                  StartRoutine,
      PVOID                  ArgumentContext,
      ULONG                  CreateFlags,
      ULONG_PTR              ZeroBits,
      SIZE_T                 StackSize,
      SIZE_T                 MaximumStackSize,
      PVOID                  AttributeList);

    

  
    typedef NTSTATUS (WINAPI *RtlDecompressBuffer_t)(
      USHORT                 CompressionFormatAndEngine,
      PUCHAR                 UncompressedBuffer,
      ULONG                  UncompressedBufferSize,
      PUCHAR                 CompressedBuffer,
      ULONG                  CompressedBufferSize,
      PULONG                 FinalUncompressedSize);
      
      

    typedef NTSTATUS(NTAPI *NtUnmapViewOfSection_t)(
      HANDLE ProcessHandle,
      PVOID BaseAddress);

    typedef enum _SECTION_INHERIT {
      ViewShare = 1,
      ViewUnmap = 2
    } SECTION_INHERIT, * PSECTION_INHERIT;

    typedef NTSTATUS(NTAPI *NtMapViewOfSection_t)(
      HANDLE SectionHandle,
      HANDLE ProcessHandle,
      PVOID *BaseAddress,
      ULONG_PTR ZeroBits,
      SIZE_T CommitSize,
      PLARGE_INTEGER SectionOffset,
      PSIZE_T ViewSize,
      SECTION_INHERIT InheritDisposition,
      ULONG AllocationType,
      ULONG Win32Protect);

    typedef NTSTATUS(NTAPI *NtCreateSection_t)(
      PHANDLE SectionHandle,
      ACCESS_MASK DesiredAccess,
      PVOID ObjectAttributes,
      PLARGE_INTEGER MaximumSize,
      ULONG SectionPageProtection,
      ULONG AllocationAttributes,
      HANDLE FileHandle);

    typedef NTSTATUS(NTAPI *NtOpenSection_t)(
      PHANDLE SectionHandle,
      ACCESS_MASK DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes);

    typedef NTSTATUS(NTAPI *NtOpenFile_t)(
      PHANDLE FileHandle,
      ACCESS_MASK DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      PIO_STATUS_BLOCK IoStatusBlock,
      ULONG ShareAccess,
      ULONG OpenOptions);

    
    /*
    */

 #endif
 
 
