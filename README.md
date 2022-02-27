# Porth

See [tsoding's YouTube playlist about Porth](https://www.youtube.com/playlist?list=PLpM-Dvs8t0VbMZA7wW9aR3EtBqe2kinu4).

**This version of Porth is currently designed to be compiled and run on macOS!**

It's like Forth but in Python. But I don't actually know since I never programmed in Forth, I only heard that it's some sort of stack-based programming language. Porth is also stack-based programming language. Which makes it just like Forth am I right?

Porth is planned to be:
- [x] Compiled
- [x] Native
- [x] Stack-based (just like Forth)
- [ ] Turing-complete (yes, the development is at such an early stage that this thing is not even Turing complete yet)
- [ ] Statically typed (the type checking is probably gonna be similar to the [WASM validation](https://binji.github.io/posts/webassembly-type-checking/))
- [ ] Self-hosted (Python is used only as an initial bootstrap, once the language is mature enough we're gonna rewrite it in itself)

## Quick Start

```console
$ python3 porth.py sim ./examples/test.porth
$ python3 /porth.py com ./examples/test.porth
$ ./output
```
