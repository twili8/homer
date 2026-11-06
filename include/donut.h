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

#ifndef DONUT_H
#define DONUT_H

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#ifndef LOADER_H
#include "mmap.h"
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#define strcasecmp stricmp
#endif
#else
#define LINUX
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "pe.h"
#endif

#ifndef LOADER_H

#if defined(dbg)
 #define DPRINT(...) { \
   fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
   fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#endif

#include "errors.h"      // Donut errors
#include "hash.h"        // api hashing
#include "encrypt.h"     // symmetric encryption of instance+module
#include "format.h"      // output format for loader

#ifndef MAX_PATH
 #define MAX_PATH 260
#endif

#if !defined(WINDOWS)
#define strnicmp(x,y,z) strncasecmp(x,y,z)
typedef uint64_t ULONG64, *PULONG64;
typedef uint32_t DWORD, *PDWORD;
typedef uint16_t WORD, *PWORD;
typedef uint8_t  BYTE, *PBYTE;

typedef char     CHAR, *PCHAR;
typedef size_t SIZE_T;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;
#endif

#define DONUT_KEY_LEN                    16
#define DONUT_BLK_LEN                    16

// target architecture
#define DONUT_ARCH_ANY                  -1  // for vbs and js files
#define DONUT_ARCH_X86                   1  // x86
#define DONUT_ARCH_X64                   2  // AMD64
#define DONUT_ARCH_X84                   3  // x86 + AMD64

// module type
#define DONUT_MODULE_NET_DLL             1  // .NET DLL. Requires class and method
#define DONUT_MODULE_NET_EXE             2  // .NET EXE. Executes Main if no class and method provided
#define DONUT_MODULE_DLL                 3  // Unmanaged DLL, function is optional
#define DONUT_MODULE_EXE                 4  // Unmanaged EXE
#define DONUT_MODULE_VBS                 5  // VBScript
#define DONUT_MODULE_JS                  6  // JavaScript or JScript
#define DONUT_MODULE_SC                  7  // Raw position-independent shellcode

// format type
#define DONUT_FORMAT_BINARY              1
#define DONUT_FORMAT_BASE64              2
#define DONUT_FORMAT_C                   3
#define DONUT_FORMAT_RUBY                4
#define DONUT_FORMAT_PYTHON              5
#define DONUT_FORMAT_POWERSHELL          6
#define DONUT_FORMAT_CSHARP              7
#define DONUT_FORMAT_HEX                 8

// compression engine
#define DONUT_COMPRESS_NONE              1
#define DONUT_COMPRESS_APLIB             2
#define DONUT_COMPRESS_LZNT1             3  // COMPRESSION_FORMAT_LZNT1
#define DONUT_COMPRESS_XPRESS            4  // COMPRESSION_FORMAT_XPRESS

// entropy level
#define DONUT_ENTROPY_NONE               1  // don't use any entropy
#define DONUT_ENTROPY_RANDOM             2  // use random names
#define DONUT_ENTROPY_DEFAULT            3  // use random names + symmetric encryption

// misc options
#define DONUT_OPT_EXIT_THREAD            1  // after the main shellcode ends, return to the caller which eventually calls RtlExitUserThread
#define DONUT_OPT_EXIT_PROCESS           2  // after the main shellcode ends, call RtlExitUserProcess to terminate host process
#define DONUT_OPT_EXIT_BLOCK             3  // after the main shellcode ends, do not exit or cleanup and block indefinitely

// instance type
#define DONUT_INSTANCE_EMBED             1  // Module is embedded

// AMSI/WLDP/ETW level

// Preserve PE headers options
#define DONUT_HEADERS_OVERWRITE          1  // Overwrite PE headers
#define DONUT_HEADERS_KEEP               2  // Preserve PE headers

#define DONUT_MAX_NAME                 256  // maximum length of string for domain, class, method and parameter names
#define DONUT_MAX_MODNAME                8
#define DONUT_SIG_LEN                    8  // 64-bit string to verify decryption ok

#define NTDLL_DLL    "ntdll.dll"
#define KERNEL32_DLL "kernel32.dll"

// Per the ECMA spec, the section data looks like this:
typedef struct _file_info_t {
    int      fd;
    uint32_t len, zlen;
    uint8_t  *data, *zdata;
    
    // the following are set for unmanaged or .NET PE/DLL files
    int      type;    
    int      arch;
} file_info;

typedef struct _API_IMPORT {
    const char *module;
    const char *name;
} API_IMPORT, *PAPI_IMPORT;

typedef struct _DONUT_CRYPT {
    uint8_t  mk[DONUT_KEY_LEN];   // master key
    uint8_t  ctr[DONUT_BLK_LEN];  // counter + nonce
} DONUT_CRYPT, *PDONUT_CRYPT;

// everything required for a module goes in the following structure
typedef struct _DONUT_MODULE {
    int      type;                            // unmanaged PE or raw shellcode
    int      thread;                          // run entrypoint of unmanaged EXE as a thread
    int      compress;                        // indicates engine used for compression
    
    char     method[DONUT_MAX_NAME];          // name of DLL function to invoke for unmanaged DLL
    
    char     args[DONUT_MAX_NAME];            // string arguments for both managed and unmanaged DLL/EXE
    int      unicode;                         // convert param to unicode for unmanaged DLL function
    
    char     sig[DONUT_SIG_LEN];              // string to verify decryption
    uint64_t mac;                             // hash of sig, to verify decryption was ok
    
    uint32_t zlen;                            // compressed size of EXE/DLL/JS/VBS file
    uint32_t len;                             // real size of EXE/DLL/JS/VBS file
    uint8_t  data[4];                         // data of EXE/DLL/JS/VBS file
} DONUT_MODULE, *PDONUT_MODULE;

// everything required for an instance goes into the following structure
#ifndef HOMER_LAYOUT_HEADER
#define HOMER_LAYOUT_HEADER "homer_layout.h"
#endif
#include HOMER_LAYOUT_HEADER


typedef struct _DONUT_CONFIG {
    uint32_t        len, zlen;                // original length of input file and compressed length
    // general / misc options for loader
    int             arch;                     // target architecture
    int             headers;                  // preserve PE headers option
    int             pack;                     // Homer: pack (encrypt) the loader at rest
    int             no_pack;                  // Homer: disable packing
    int             compress;                 // engine to use when compressing file via RtlCompressBuffer
    int             entropy;                  // entropy/encryption level
    int             format;                   // output format for loader
    int             exit_opt;                 // return to caller, invoke RtlExitUserProcess to terminate the host process, or block indefinitely
    int             thread;                   // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
    
    // files in/out
    char            input[DONUT_MAX_NAME];    // name of input file to read and load in-memory
    char            output[DONUT_MAX_NAME];   // name of output file to save loader
    
    char            method[DONUT_MAX_NAME];   // name of DLL function to invoke for unmanaged DLL
    
    // command line for DLL/EXE
    char            args[DONUT_MAX_NAME];    // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    int             unicode;                  // param is passed to DLL function without converting to unicode

    // Homer: DLLs to unhook by remapping and redirecting PEB LDR entries
    char            unhook[DONUT_MAX_NAME];   // semicolon-separated DLL names

    // DONUT_MODULE
    int             payload_type;             // 1=auto-detect, 2=raw shellcode
    int             mod_type;                 // VBS/JS/DLL/EXE/SC/SC
    int             mod_len;                  // size of DONUT_MODULE
    DONUT_MODULE    *mod;                     // points to DONUT_MODULE
    
    // DONUT_INSTANCE
    int             inst_type;                // always DONUT_INSTANCE_EMBED
    int             inst_len;                 // size of DONUT_INSTANCE
    DONUT_INSTANCE  *inst;                    // points to DONUT_INSTANCE
    
    // shellcode generated from configuration
    int             pic_len;                  // size of loader/shellcode
    void*           pic;                      // points to loader/shellcode
} DONUT_CONFIG, *PDONUT_CONFIG;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DLL
#define EXPORT_FUNC __declspec(dllexport)
#else
#define EXPORT_FUNC
#endif

// public functions
EXPORT_FUNC int DonutCreate(PDONUT_CONFIG);
EXPORT_FUNC int DonutDelete(PDONUT_CONFIG);
EXPORT_FUNC const char* DonutError(int);

#ifdef __cplusplus
}
#endif

#endif
