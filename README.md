# VoidBreaker

A single-file static vulnerability scanner written in **C with embedded x86-64 assembly**.

Point it at a file — source code or a compiled binary — and it flags risky
patterns, explains why they're risky, and (for binaries) disassembles the
file and reports which hardening protections are missing.

VoidBreaker is a **detection tool only**. It does not generate exploits,
payloads, or shellcode — it finds and explains risky patterns, the same way
tools like `flawfinder`, `cppcheck`, or `checksec` do.

```
 ▄█    █▄   ▄██████▄   ▄█  ████████▄  ▀█████████▄     ▄████████    ▄████████    ▄████████    ▄█   ▄█▄    ▄████████    ▄████████
███    ███ ███    ███ ███  ███   ▀███   ███    ███   ███    ███   ███    ███   ███    ███   ███ ▄███▀   ███    ███   ███    ███
███    ███ ███    ███ ███▌ ███    ███   ███    ███   ███    ███   ███    █▀    ███    ███   ███▐██▀     ███    █▀    ███    ███
███    ███ ███    ███ ███▌ ███    ███  ▄███▄▄▄██▀   ▄███▄▄▄▄██▀  ▄███▄▄▄       ███    ███  ▄█████▀     ▄███▄▄▄      ▄███▄▄▄▄██▀
███    ███ ███    ███ ███▌ ███    ███ ▀▀███▀▀▀██▄  ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ▀███████████ ▀▀█████▄    ▀▀███▀▀▀     ▀▀███▀▀▀▀▀
███    ███ ███    ███ ███  ███    ███   ███    ██▄ ▀███████████   ███    █▄    ███    ███   ███▐██▄     ███    █▄  ▀███████████
███    ███ ███    ███ ███  ███   ▄███   ███    ███   ███    ███   ███    ███   ███    ███   ███ ▀███▄   ███    ███   ███    ███
 ▀██████▀   ▀██████▀  █▀   ████████▀  ▄█████████▀    ███    ███   ██████████   ███    █▀    ███   ▀█▀   ██████████   ███    ███
```

## Build

One file, no external dependencies beyond a standard C toolchain:

```bash
gcc -O2 -o voidbreaker voidbreaker.c
```

The x86-64 pattern-matching routine (`asm_find`) is written directly in
assembly (GNU `as`, Intel syntax) and embedded in `voidbreaker.c` via a
top-level `asm()` block, so the whole tool still compiles from a single
source file.

## Usage

```bash
./voidbreaker <file-to-scan>
```

VoidBreaker always works on a **copy** of the target file — saved under
`voidbreaker_scans/` — so the original is never modified.

### Source code mode

If the file is recognized source code, VoidBreaker scans it line by line
for risky patterns and prints the file, line number, vulnerability type,
risk level, and a short explanation for each finding.

```bash
./voidbreaker login.c
```

```
[!] login.c:9
    Type   : Buffer Overflow
    Risk   : HIGH
    Match  : strcpy(
    Why    : strcpy() does not bound-check the destination buffer.
```

### Binary mode

If the file is a compiled binary (ELF executable, ELF object `.o`, or a
PE `.exe`), VoidBreaker:

1. Disassembles the copy with `objdump -d -M intel`, saving the full
   listing as `<copy>.asm`
2. Scans that listing for calls to risky library functions
3. Runs a `checksec`-style hardening check via `readelf`: RELRO, PIE,
   NX-stack, and stack-canary presence

```bash
./voidbreaker ./some_binary
```

```
[*] Hardening check (readelf):
    [!] RELRO       : Partial/None (no BIND_NOW) - GOT is more writable
    [!] PIE         : Disabled (ET_EXEC) - fixed load address aids exploitation
    [!] NX stack    : Disabled (stack is executable)
    [!] Canary      : Not found - stack smashing may go undetected

[!] some_binary.copy.asm:42 (disassembly)
    Type   : Buffer Overflow
    Risk   : CRITICAL
    Instr  : 00000000004010a0 <gets@plt>:
    Why    : Call to gets - classic unbounded stdin read, easiest stack smash.
```

## How file type and language are detected

- **Binary vs. source** is detected by magic bytes first (`\x7fELF` for
  ELF, `MZ` for PE), then by file extension, then by whether the content
  looks like printable text.
- **Source language** is detected by extension and determines which rule
  set is used:

| Extension | Language |
|---|---|
| `.c .h .cpp .cc .hpp .cxx` | C/C++ |
| `.py` | Python |
| `.js .ts .jsx .tsx` | JavaScript/TypeScript |
| `.php` | PHP |
| `.java` | Java |
| `.go` | Go |
| `.rb` | Ruby |
| `.sh .bash` | Shell |
| anything else | generic fallback rules |

## What it looks for

**C/C++:** `strcpy`/`strcat`/`gets`/`sprintf`/`scanf` (buffer overflow),
`memcpy`, `strtok` (thread-safety), `system`/`popen` (command injection),
`strncpy` (unterminated string), `rand`/`srand` (weak randomness),
`tmpnam`/`mktemp` (insecure temp files), `alloca`, plus a heuristic for
`printf`/`fprintf`/`syslog` called with a non-literal format string
(format string bugs).

**Python:** `eval`/`exec`, `os.system`/`os.popen`, `shell=True`,
`pickle.loads`/`yaml.load`/`marshal.loads` (insecure deserialization),
`__import__`.

**JavaScript/TypeScript:** `eval`, `new Function`,
`child_process.exec`, `document.write`/`.innerHTML`/
`dangerouslySetInnerHTML` (XSS), dynamic `require`.

**PHP:** `eval`, `system`/`exec`/`shell_exec`/`passthru`,
`unserialize` (insecure deserialization), dynamic `include`/`require`
(LFI/RFI), `md5` (weak hash), `extract`.

**Java:** `Runtime.exec`/`ProcessBuilder`, `readObject`
(deserialization), `Class.forName`, `MessageDigest("MD5")`,
`Cipher.getInstance("DES...")`.

**Go:** `exec.Command`, `unsafe.Pointer`, `md5.New`, `text/template`
vs. `html/template` misuse.

**Ruby:** `eval`, `system`, backtick execution, `Marshal.load`,
`YAML.load`.

**Shell:** `eval`, piping into `sh`/`bash` (remote code execution),
`chmod 777`, unquoted `rm -rf $VAR`.

**Binaries (via disassembly):** all of the C-family libc calls above,
plus the full `exec*` family, `setuid`, `chmod`, and fortified
`__strcpy_chk`.

## Project layout

```
voidbreaker.c   - the entire tool (scanner logic + embedded asm)
README.md       - this file
```

Everything lives in `voidbreaker.c` by design — compile it, run it, done.

## Limitations

- This is a **heuristic pattern scanner**, not a compiler or a real
  dataflow/taint analyzer — it flags lines *worth reviewing*, not
  confirmed exploitable bugs. Expect some false positives (e.g. a
  `strncpy` call that's actually safe) and false negatives (e.g. a
  buffer overflow hidden behind a wrapper function).
- Binary-mode detection relies on the function names still being visible
  (`@plt` symbols) — a fully static binary or a stripped binary won't
  show those names.
- It does not generate exploits, offsets, or payloads, by design.
