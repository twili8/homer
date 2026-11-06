# Homer

Homer is a fork of [donut](https://github.com/TheWover/donut) hardened against
static extraction by tools such as
[donut-decryptor](https://github.com/volexity/donut-decryptor). It keeps donut's
output formats and most of its CLI. Every invariant a static extractor relies
on is either gone or moved behind a per-build secret, so there are no stable
byte offsets left to parse.

Payload support is deliberately narrow: unmanaged PE (EXE/DLL) and raw
position-independent shellcode.

## What changed vs. donut v1.0

| Layer | Donut (upstream) | Homer |
|---|---|---|
| Loader bytes at rest | Final-form compiled loader (fixed YARA signature) | A small per-build stub decrypts the body at runtime |
| Instance locator | `call rel32` ... `pop rcx`, instance contiguous, <=11-byte window | Packing removes the static preamble entirely |
| Struct layout | Compile-time constant per version (hard-coded in parsers) | Per-build randomized padding + shuffled field groups, plus one of two precompiled variants picked per payload |
| Oracles in plaintext | `entropy`, `exit_opt`, `api` hash table in the clear | Moved into the ciphertext region |
| Key material | `instance_key`/`module_key` readable in the instance | Bootstrap fields masked with a KDF over a per-build salt |
| Output formats | Fixed headers, wrap widths, standard base64 alphabet | Randomized identifiers/spacing/wrapping, custom base64 alphabet |
| Mapped-module visibility | Invisible to module lists | Linked into `InLoadOrderModuleList`/`InMemoryOrderModuleList` |
| Import names in memory | Hint/name and DLL-name strings readable after binding | Zeroed after binding, bounded by `SizeOfImage` |
| Loader stub | One form | Two polymorphic variants, picked per payload |
| AMSI/WLDP/ETW bypass | Three bypass subsystems with signatured strings | Removed |
| HTTP staging | wininet.dll plus download helpers | Removed |
| Kernel32 API surface | 25 kernel32 calls (VirtualAlloc, Sleep, CreateThread, etc.) | ntdll or intrinsic equivalents |
| String conversion | RtlMultiByteToUnicodeN, RtlCreateUnicodeString, RtlUnicodeStringToAnsiString | Custom implementations |
| Sleep | NtDelayExecution (VMs can skip) | PAUSE busy-wait |
| RtlExitUserProcess | RtlExitUserProcess | NtTerminateProcess |
| Hooked DLLs | EDR hooks live in ntdll/kernel32 `.text`; un-hooking rewrites `.text` (RWX transition) | Optional remap of user-listed DLLs from `\KnownDlls`/disk into fresh images; PEB LDR entries patched (no writes to the dirty image) |

## Build

```
make -f Makefile.homer all          # loaders + stubs + generator (seed 1)
make -f Makefile.homer all SEED=42  # rotate the instance layout
```

Requires: `gcc`, `i686-w64-mingw32-gcc`, `x86_64-w64-mingw32-gcc`,
`python3` with `pefile`. Produces `./homer`. Generated headers and bindings
land under `build/c` and `build/go`; only the linked binaries land at the
repo root.

## Usage

```
homer --arch:2 -i payload.exe -o out.bin            # packed (default)
homer --arch:2 -i payload.exe -o out.bin --no-pack  # unpacked (inspectable)
homer --arch:2 -f:8 -i payload.exe -o out.hex       # randomized hex format
homer --arch:2 -u "ntdll.dll;kernel32.dll" -i payload.exe -o out.bin
homer -i shellcode.bin -T 2 -o out.bin              # raw shellcode payload
homer -P jobs.toml -o out/                          # batch build
```

`-T 2` treats the input as flat position-independent code: no PE parsing, no
section mapping. The loader copies it to its own allocation, makes it
executable and calls it once with the PEB in RCX.

`-P` builds every job in a profile file; see `docs/profiles.md`.

## Flags

Short and long forms are equivalent; a value takes `:` on the short form
(`--arch:2`) or `=` on the long form (`--arch=2`).

| Flag | Values | Default | Meaning |
|---|---|---|---|
| `-a`/`--arch` | `1`/`x86`, `2`/`x64`, `3` dual | `3` dual | target architecture |
| `-f`/`--format` | `bin`, `base64`, `c`, `ruby`, `python`, `powershell`, `csharp`, `hex`, or `1`-`8` | `bin` | output encoding |
| `-e`/`--entropy` | `1` none, `2` random names, `3` names + encryption | `3` | per-payload randomness |
| `-T`/`--type` | `1` auto, `2` raw shellcode | `1` | `-T 2` skips PE parsing |
| `-x`/`--exit` | `1`/`thread`, `2`/`process`, `3`/`block` | `1` | what the loader does after the payload returns |
| `-t`/`--thread` | flag | off | run an EXE payload on its own thread |
| `-u`/`--unhook` | `"dll1;dll2"` | empty | remap these DLLs from clean images (operator pass) |
| `-z`/`--compress` | `1` none, `3` LZNT1, `4` XPRESS | `1` | module compression (Rtl engines need a Windows host to compress) |
| `-k`/`--headers` | `1` overwrite, `2` keep | `1` | PE header handling |
| `-P`/`--profile` | path | n/a | batch build; `-o` is the output directory |
| `-K`/`--pack` | flag | on | pack the loader at rest (`--no-pack` disables) |

## Operator passes

The loader core decrypts, maps, binds and jumps. Everything else is a pass in
`passes/`: one `HOMER_REGISTER(name, stage)` marker plus one
`homer_pass__name` function.

- `HOMER_PRE_MAP` runs after the bootstrap decrypt/MAC check and the
  instance copy, before any loader API is resolved. Only `inst` is valid;
  `mod`, `base` and `nt` are NULL.
- `HOMER_PRE_JUMP` runs after the PE image is bound (imports resolved),
  while it is still writable: before headers are wiped, protections are set,
  TLS callbacks run, or any entry point is invoked. All four arguments are
  valid. PE payloads only: raw shellcode has no image and no jump point to
  hook.

Any pass returns nonzero to abort the load. The loader wipes the instance
and returns without jumping. Passes have no isolation from each other or the
loader; a crashing pass kills the load by design, so keep them small and
review them like loader code.

`tools/gen_passes.py` scans `passes/` and emits a direct-call dispatcher into
`build/c/passes_gen.c`. The dispatcher uses direct calls, not a function
table: the release loader runs unrelocated, so absolute addresses in `.rdata`
would be garbage. There is no runtime registry and no pass limit. The build
enforces two gates:

- source gate: direct Win32 calls (`LoadLibrary`, `GetProcAddress`,
  `VirtualAlloc`, `CreateThread`, …), `dllimport` and `#pragma comment(lib)`
  fail with file:line. Resolve everything through the PEB (`inst->api`,
  `xGetProcAddressByHash`).
- import gate: `python3 tools/gen_passes.py --check-imports <artifact>`
  fails any release artifact with an import table. The loader and the DLL
  must import nothing.

See `passes/README.md` for the authoring rules.

### Unhooking (`passes/unhook.c`, on by default)

`-u/--unhook` takes a semicolon-separated list of DLLs (up to 16). For each
name the pass:

1. maps a fresh image from `\KnownDlls\<name>` (shared section), falling back
   to a `SEC_IMAGE` mapping of the module's `FullDllName` on disk;
2. binds the fresh image's import and delay-import tables against the clean
   image set (unlisted dependencies resolve through the PEB);
3. rewrites `DllBase`, `EntryPoint`, `SizeOfImage`, `OriginalBase` and
   `ParentDllBase` in the LDR entry.

The original (possibly hooked) mapping is never made writable or executable,
so the rewrite does not generate a `+X` protection transition on the image
the EDR instrumented. To drop unhooking entirely, delete the file; the DLL
host build already excludes it.

### Import-name scrubbing (`passes/scrub.c`, on by default)

Once a mapped module's imports are bound, the loader zeroes the hint/name and
DLL-name strings in the mapped copy. The disk image is untouched and directory
RVAs stay intact, so binding still works; a memory scan just no longer finds
the payload's API surface for free. Build-time switch:
`-DHOMER_SCRUB_IMPORTS=0` to keep the names. The scrubber is bounded by
`SizeOfImage`, so a malformed or relocated name cannot run past the image.

## DLL host build

The loader can be built as a DLL whose `DllMain` starts the payload on a
detached worker thread:

```
./homer --arch:2 -i payload.exe -o instance.bin --no-pack -t
make -f Makefile.homer dll INSTANCE=instance.bin
# -> homer_loader.dll
```

The `--no-pack` output is a complete PIC (`E8 <len32> <instance> 59 <loader>`),
so `tools/bin2h.py --instance` embeds only the instance bytes. The DLL omits
`loader/entry.S`; `DllMain` is the entry point, linked without a CRT.

`DllMain` only copies the embedded (const) instance into writable memory and
creates one detached worker with `NtCreateThreadEx`. It never waits or joins.
The worker runs `DonutLoader`, then wipes and releases the copy; `DonutLoader`
unwraps the instance into its own allocation, so the copy is dead by then.
The payload therefore starts from `DLL_PROCESS_ATTACH` without blocking the
loader lock.

For an EXE payload, generate the instance with `-t`. The payload then runs on
its own thread and its `ExitProcess` import is redirected to
`RtlExitUserThread`, so the host survives and `DonutLoader` returns. Without
`-t` the payload's exit ends the whole host process.

## Honest limits

* Homer payloads are self-contained, so the key is a deterministic function of
  the payload bytes: a determined analyst can always unpack by emulating or
  disassembling the stub. Static defenses make extraction require program
  understanding instead of byte-offset lookup; they do not provide
  information-theoretic secrecy. True secrecy needs a secret outside the
  payload (C2, environment, user), which conflicts with a standalone design.
* No static defense beats dynamic analysis: running the loader and dumping
  memory recovers the module. Runtime anti-analysis (anti-VM, anti-debug,
  integrity checks) is out of scope for this fork.
* Layout randomization has two layers: the base layout is per *build* (SEED),
  and each payload additionally picks one of two precompiled layout variants
  at generation time. Rotating the base layout per payload would require
  recompiling the loader per generation.
* There is no hosted debug build; the release loader is raw shellcode, so
  debug it by attaching to the host process.

The reasoning behind the loader design, and the full `LoadLibrary` path it is
derived from, is in [here](https://twili8.github.io/2026/11/05/ntdll.html)!
