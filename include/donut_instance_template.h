typedef struct _DONUT_INSTANCE {
    uint32_t    len;                          // total size of instance
    DONUT_CRYPT key;                          // decrypts instance if encryption enabled

    uint64_t    iv;                           // the 64-bit initial value for maru hash

    // everything from here is encrypted (Homer L4).
int         api_cnt;                      // the 64-bit hashes of API required for instance to work


    union {
      uint64_t  hash[64];                     // holds up to 64 api hashes
      void     *addr[64];                     // holds up to 64 api addresses
      // include prototypes only if header included from loader.h
      #ifdef LOADER_H
      struct {
        // imports from kernel32.dll or kernelbase.dll
        LoadLibraryA_t                   LoadLibraryA;
        GetProcAddress_t                 GetProcAddress;
        GetModuleHandleA_t               GetModuleHandleA;
        NtAllocateVirtualMemory_t     NtAllocateVirtualMemory;
        NtFreeVirtualMemory_t          NtFreeVirtualMemory;
        NtQueryVirtualMemory_t         NtQueryVirtualMemory;
        NtProtectVirtualMemory_t       NtProtectVirtualMemory;
        NtWaitForSingleObject_t        NtWaitForSingleObject;
        NtCreateThreadEx_t             NtCreateThreadEx;
        RtlAllocateHeap_t                RtlAllocateHeap;
        NtClose_t                        NtClose;

        // imports from ntdll.dll
        RtlExitUserThread_t              RtlExitUserThread;
        NtTerminateProcess_t             NtTerminateProcess;
        RtlDecompressBuffer_t            RtlDecompressBuffer;
        NtCreateSection_t                NtCreateSection;
        NtMapViewOfSection_t             NtMapViewOfSection;
        NtUnmapViewOfSection_t           NtUnmapViewOfSection;
      };
      #endif
    } api;
    
    int         exit_opt;                     // 1 to call RtlExitUserProcess and terminate the host process, 2 to never exit or cleanup and block
    int         entropy;                      // indicates entropy level

    // everything from here is encrypted
    char        dll_names[DONUT_MAX_NAME];    // a list of DLL strings to load, separated by semi-colon
    char        unhook[DONUT_MAX_NAME];       // DLLs to re-map from KnownDlls/disk, separated by semi-colon

    char        dataname[8];                  // ".data"
    char        kernelbase[12];               // "kernelbase"

    char        cmd_syms[DONUT_MAX_NAME];     // symbols related to command line
    char        exit_api[DONUT_MAX_NAME];     // exit-related API

    int         headers;                      // indicates whether to overwrite PE headers

    uint8_t     sig[DONUT_MAX_NAME];        // string to hash
    uint64_t    mac;                        // to verify decryption ok
    
    DONUT_CRYPT mod_key;       // used to decrypt module
    uint64_t    mod_len;       // total size of module
    
    union {
      PDONUT_MODULE p;         // Memory allocated for module downloaded via DNS or HTTP
      DONUT_MODULE  x;         // Module is embedded
    } module;
} DONUT_INSTANCE, *PDONUT_INSTANCE;
