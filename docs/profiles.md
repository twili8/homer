# Batch builds from a profile

`homer -P jobs.toml -o out/` builds every job in one invocation. The format is
`[section]` headers and `key = value` lines: ini-style, not real TOML, so no
nesting, no arrays, no quoted multiline strings. Unknown keys print a warning
and are ignored, so a profile written for a newer build still does what it
can (see Exit status).

```
# applied to every job
[default]
arch   = 2
entropy = 1

[job]
input  = payloads/one.dll
method = Run
output = out/one.bin

[job]
input  = payloads/two.exe
format = base64
```

## Keys

| Key | Values | Default |
|---|---|---|
| `input` / `file` | path | required |
| `output` | path | derived from `-o` |
| `arch` / `cpu` | `1`/`x86`, `2`/`x64`, `3` dual, `any` (= `3`; same as CLI `--arch`) | `3` (dual) |
| `format` | `bin`, `base64`, `c`, `ruby`, `python`, `powershell`, `csharp`, `hex`, or `1`-`8` in that order (same as CLI `--format`) | `bin` |
| `entropy` | `1` none, `2` random names, `3` names + encryption | `3` |
| `compress` | `1` none, `3` LZNT1, `4` XPRESS | `1` |
| `headers` | `1` overwrite, `2` keep | `1` |
| `exit` | `thread`, `process`, `block` (= CLI `-x 1/2/3`: what the loader does after the payload returns) | `thread` |
| `thread` | `true` / `false` (= CLI `-t`: run an EXE payload on its own thread so its exit does not kill the host) | `false` |
| `unicode` | `true` / `false` (command line to a DLL function in UNICODE instead of ANSI) | `false` |
| `pack` / `no_pack` | `true` / `false` | pack on |
| `type` | `1` auto, `2` raw shellcode (= CLI `-T`) | `1` |
| `method`/`function`, `args`/`params` | strings (`method`/`args` used for unmanaged DLLs) | empty |
| `unhook` | `"dll1;dll2"` string (= CLI `-u`) | empty |

## Output naming

* `-o DIR` plus a job `output` that is relative → `DIR/<output>`.
* `-o DIR` and no job `output` → `DIR/<input stem>.<format ext>`.
* No `-o` and no job `output` → `loader.bin` (same default as the CLI).
* Absolute job `output` is used as-is.

Two jobs with the same input and format would collide; give one an explicit
`output`.

## Exit status

`0` when every job built, `1` when any job failed. Each job's error is printed
as it happens, so a batch run shows which payload broke.

## Raw shellcode payloads

`type = 2` (or `-T 2` on the command line) treats the input as flat
position-independent code: no PE parsing, no extension check, no section
mapping. The loader copies it to its own allocation, makes it executable and
calls it once with the PEB in RCX. Nothing is registered in the PEB, because
there is no image to register.
