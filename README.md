# Homer

Homer is a fork of [donut](https://github.com/TheWover/donut) hardened against
static extraction by tools such as
[donut-decryptor](https://github.com/volexity/donut-decryptor).

Educational and defensive research purposes only. Use only on systems you own or are authorised to test. No warranty are offered, no liability for misuse. Do not use illegal actions.

See [HOMER.md](HOMER.md) for the security model, build instructions, and usage.

## Build

```
make -f Makefile.homer all
```

Requires `gcc`, `i686-w64-mingw32-gcc`, `x86_64-w64-mingw32-gcc`, and
`python3` with `pefile`. Produces `./homer`. (`exe2h` is built from source;
no `objcopy` needed.)

## License

BSD 3-Clause. See [LICENSE](LICENSE).
