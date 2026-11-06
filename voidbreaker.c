/*
 * voidbreaker.c
 *
 * VoidBreaker - a single-file static vulnerability scanner.
 *
 * Give it a file:
 *   - If it's C/C++ source, it scans line by line for risky patterns
 *     (strcpy, gets, sprintf, system, format-string bugs, ...).
 *   - If it's a compiled binary (ELF executable, ELF object .o, or a
 *     PE .exe), it disassembles a COPY of it with objdump into a
 *     .asm listing, scans that listing for calls to risky functions,
 *     and reports which hardening protections (NX/PIE/canary/RELRO)
 *     are present via readelf.
 *
 * The original file is never modified - a working copy is made first.
 *
 * This is a detection tool only: it finds and explains risky patterns.
 * It does not generate exploits, payloads, or shellcode.
 *
 * Build (single file, no external deps beyond the C toolchain):
 *   gcc -O2 -o voidbreaker voidbreaker.c
 *
 * The x86-64 pattern-matching routine below is written directly in
 * assembly and embedded in this same source file via GCC's top-level
 * asm() block, so the whole tool still compiles from one file.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* x86-64 assembly: fast substring search, embedded in this .c file   */
/*                                                                     */
/* long asm_find(const char *haystack, long hlen,                     */
/*                const char *needle,   long nlen);                   */
/*                                                                     */
/* System V AMD64 ABI: rdi=haystack, rsi=hlen, rdx=needle, rcx=nlen    */
/* Returns index of first match, or -1 if the needle isn't found.     */
/* ------------------------------------------------------------------ */
__asm__(
    ".intel_syntax noprefix\n"
    ".text\n"
    ".globl asm_find\n"
    ".type asm_find, @function\n"
"asm_find:\n"
    "    push rbx\n"
    "    push r12\n"
    "    push r13\n"
    "    push r14\n"

    "    mov r8,  rdi\n"          /* haystack ptr            */
    "    mov r9,  rsi\n"          /* hlen                    */
    "    mov r10, rdx\n"          /* needle ptr              */
    "    mov r11, rcx\n"          /* nlen                    */

    "    cmp r11, 0\n"
    "    je  .Lnot_found\n"        /* empty needle -> not found      */
    "    cmp r9, r11\n"
    "    jl  .Lnot_found\n"        /* haystack shorter than needle   */

    "    xor r12, r12\n"           /* r12 = i (start index)          */
    "    mov r13, r9\n"
    "    sub r13, r11\n"           /* r13 = last valid start index   */

".Louter:\n"
    "    cmp r12, r13\n"
    "    jg  .Lnot_found\n"

    "    xor r14, r14\n"           /* r14 = j (needle index)         */
".Linner:\n"
    "    cmp r14, r11\n"
    "    jge .Lmatch\n"            /* matched all needle bytes       */

    "    mov rbx, r12\n"
    "    add rbx, r14\n"
    "    movzx eax, byte ptr [r8 + rbx]\n"
    "    movzx edx, byte ptr [r10 + r14]\n"
    "    cmp al, dl\n"
    "    jne .Lnext\n"

    "    inc r14\n"
    "    jmp .Linner\n"

".Lnext:\n"
    "    inc r12\n"
    "    jmp .Louter\n"

".Lmatch:\n"
    "    mov rax, r12\n"
    "    jmp .Ldone\n"

".Lnot_found:\n"
    "    mov rax, -1\n"

".Ldone:\n"
    "    pop r14\n"
    "    pop r13\n"
    "    pop r12\n"
    "    pop rbx\n"
    "    ret\n"
    ".size asm_find, . - asm_find\n"
    ".att_syntax prefix\n"
);

extern long asm_find(const char *haystack, long hlen, const char *needle, long nlen);

static long asm_find_str(const char *haystack, const char *needle) {
    return asm_find(haystack, (long)strlen(haystack), needle, (long)strlen(needle));
}

/* ------------------------------------------------------------------ */
/* Banner                                                              */
/* ------------------------------------------------------------------ */
static const char *BANNER =
" ▄█    █▄   ▄██████▄   ▄█  ████████▄  ▀█████████▄     ▄████████    ▄████████    ▄████████    ▄█   ▄█▄    ▄████████    ▄████████\n"
"███    ███ ███    ███ ███  ███   ▀███   ███    ███   ███    ███   ███    ███   ███    ███   ███ ▄███▀   ███    ███   ███    ███\n"
"███    ███ ███    ███ ███▌ ███    ███   ███    ███   ███    ███   ███    █▀    ███    ███   ███▐██▀     ███    █▀    ███    ███\n"
"███    ███ ███    ███ ███▌ ███    ███  ▄███▄▄▄██▀   ▄███▄▄▄▄██▀  ▄███▄▄▄       ███    ███  ▄█████▀     ▄███▄▄▄      ▄███▄▄▄▄██▀\n"
"███    ███ ███    ███ ███▌ ███    ███ ▀▀███▀▀▀██▄  ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ▀███████████ ▀▀█████▄    ▀▀███▀▀▀     ▀▀███▀▀▀▀▀\n"
"███    ███ ███    ███ ███  ███    ███   ███    ██▄ ▀███████████   ███    █▄    ███    ███   ███▐██▄     ███    █▄  ▀███████████\n"
"███    ███ ███    ███ ███  ███   ▄███   ███    ███   ███    ███   ███    ███   ███    ███   ███ ▀███▄   ███    ███   ███    ███\n"
" ▀██████▀   ▀██████▀  █▀   ████████▀  ▄█████████▀    ███    ███   ██████████   ███    █▀    ███   ▀█▀   ██████████   ███    ███\n"
"                                                     ███    ███                             ▀                        ███    ███\n";

#define C_PURPLE "\x1b[38;5;141m"

static void print_banner(void) {
    printf("%s%s%s\n", C_PURPLE, BANNER, "\x1b[0m");
    printf("          static vulnerability scanner  |  C + x86-64 asm  |  detection only\n\n");
}

/* ------------------------------------------------------------------ */
/* Subprocess execution - fork()/execvp() directly, NEVER a shell.     */
/*                                                                      */
/* Every external tool VoidBreaker shells out to (objdump, readelf,    */
/* strings) is launched with an explicit argv[] array and execvp(),    */
/* so a filename can contain spaces, quotes, '$', backticks, newlines  */
/* - anything - without any risk of shell command injection. There is  */
/* no command string to build or escape, so there is nothing to get    */
/* wrong. The child's stderr is always sent to /dev/null so a missing  */
/* or failing tool doesn't spam the scan output.                       */
/* ------------------------------------------------------------------ */
typedef struct { FILE *f; pid_t pid; } ExecStream;

/* Launch argv[0] with stdout captured as a readable FILE*. Returns 0
 * on success (es->f / es->pid populated), -1 on failure. */
static int exec_popen_r(char *const argv[], ExecStream *es) {
    int fds[2];
    if (pipe(fds) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }

    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp(argv[0], argv);
        _exit(127); /* only reached if execvp failed (tool not installed) */
    }

    close(fds[1]);
    FILE *f = fdopen(fds[0], "r");
    if (!f) {
        close(fds[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }
    es->f = f;
    es->pid = pid;
    return 0;
}

static void exec_popen_close(ExecStream *es) {
    if (es->f) fclose(es->f);
    int status;
    waitpid(es->pid, &status, 0);
}

/* Launch argv[0] with stdout redirected into out_path, and wait for it
 * to finish. Returns 0 on success, -1 if the file couldn't be opened
 * or the fork failed. */
static int exec_to_file(char *const argv[], const char *out_path) {
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(fd); return -1; }

    if (pid == 0) {
        dup2(fd, STDOUT_FILENO);
        close(fd);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp(argv[0], argv);
        _exit(127);
    }

    close(fd);
    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 127) ? -1 : 0;
}

/* Read an ExecStream's full output into a buffer (like the old
 * popen()+fread() pattern, but with no shell involved). */
static int exec_capture(char *const argv[], char *out, size_t outsz) {
    ExecStream es;
    if (exec_popen_r(argv, &es) != 0) { out[0] = '\0'; return -1; }

    size_t total = 0, n;
    while (total < outsz - 1 && (n = fread(out + total, 1, outsz - 1 - total, es.f)) > 0) {
        total += n;
    }
    out[total] = '\0';
    exec_popen_close(&es);
    return (int)total;
}

/* ------------------------------------------------------------------ */
/* Output helpers: color-coded risk levels + a severity summary        */
/* ------------------------------------------------------------------ */
#define C_RESET  "\x1b[0m"
#define C_RED    "\x1b[31;1m"
#define C_ORANGE "\x1b[33;1m"
#define C_YELLOW "\x1b[33m"
#define C_CYAN   "\x1b[36m"

static const char *risk_color(const char *risk) {
    if (!strcmp(risk, "CRITICAL")) return C_RED;
    if (!strcmp(risk, "HIGH"))     return C_ORANGE;
    if (!strcmp(risk, "MEDIUM"))   return C_YELLOW;
    return C_CYAN; /* LOW */
}

typedef struct { int critical, high, medium, low; } Counts;

static void count_risk(Counts *c, const char *risk) {
    if (!strcmp(risk, "CRITICAL")) c->critical++;
    else if (!strcmp(risk, "HIGH")) c->high++;
    else if (!strcmp(risk, "MEDIUM")) c->medium++;
    else c->low++;
}

static void print_summary(const Counts *c, int findings) {
    printf("[*] Summary: %d finding(s)  -  "
           C_RED "%d critical" C_RESET ", "
           C_ORANGE "%d high" C_RESET ", "
           C_YELLOW "%d medium" C_RESET ", "
           C_CYAN "%d low" C_RESET "\n",
           findings, c->critical, c->high, c->medium, c->low);
}

/* ------------------------------------------------------------------ */
/* File type detection                                                 */
/* ------------------------------------------------------------------ */
typedef enum { FT_UNKNOWN, FT_SOURCE, FT_ELF, FT_PE } FileType;

typedef enum {
    LANG_C, LANG_PY, LANG_JS, LANG_PHP, LANG_JAVA,
    LANG_GO, LANG_RUBY, LANG_SH, LANG_RUST, LANG_KOTLIN, LANG_GENERIC
} Language;

static Language detect_language(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return LANG_GENERIC;

    if (!strcmp(ext, ".c") || !strcmp(ext, ".h") || !strcmp(ext, ".cpp") ||
        !strcmp(ext, ".cc") || !strcmp(ext, ".hpp") || !strcmp(ext, ".cxx"))
        return LANG_C;
    if (!strcmp(ext, ".py")) return LANG_PY;
    if (!strcmp(ext, ".js") || !strcmp(ext, ".ts") || !strcmp(ext, ".jsx") || !strcmp(ext, ".tsx")) return LANG_JS;
    if (!strcmp(ext, ".php")) return LANG_PHP;
    if (!strcmp(ext, ".java")) return LANG_JAVA;
    if (!strcmp(ext, ".go")) return LANG_GO;
    if (!strcmp(ext, ".rb")) return LANG_RUBY;
    if (!strcmp(ext, ".sh") || !strcmp(ext, ".bash")) return LANG_SH;
    if (!strcmp(ext, ".rs")) return LANG_RUST;
    if (!strcmp(ext, ".kt") || !strcmp(ext, ".kts")) return LANG_KOTLIN;

    return LANG_GENERIC;
}

static const char *language_name(Language lang) {
    switch (lang) {
        case LANG_C:      return "C/C++";
        case LANG_PY:     return "Python";
        case LANG_JS:     return "JavaScript/TypeScript";
        case LANG_PHP:    return "PHP";
        case LANG_JAVA:   return "Java";
        case LANG_GO:     return "Go";
        case LANG_RUBY:   return "Ruby";
        case LANG_SH:     return "Shell";
        case LANG_RUST:   return "Rust";
        case LANG_KOTLIN: return "Kotlin";
        default:          return "generic text";
    }
}

static FileType detect_file_type(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return FT_UNKNOWN;

    unsigned char magic[4] = {0};
    size_t n = fread(magic, 1, 4, f);
    fclose(f);

    if (n >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return FT_ELF;
    }
    if (n >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
        return FT_PE;
    }

    /* Not a known binary magic -> fall back to extension, then content. */
    const char *ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".c") == 0 || strcmp(ext, ".h") == 0 ||
            strcmp(ext, ".cpp") == 0 || strcmp(ext, ".cc") == 0 ||
            strcmp(ext, ".hpp") == 0 || strcmp(ext, ".cxx") == 0) {
            return FT_SOURCE;
        }
        if (strcmp(ext, ".o") == 0 || strcmp(ext, ".bin") == 0 ||
            strcmp(ext, ".exe") == 0 || strcmp(ext, ".out") == 0) {
            /* Extension says binary even though magic bytes didn't match
             * ELF/PE (e.g. raw .bin shellcode-less blob) - treat as binary
             * and let objdump do its best with it. */
            return FT_ELF;
        }
    }

    /* Last resort: does it look like printable text? */
    f = fopen(path, "rb");
    if (f) {
        int printable = 1, checked = 0;
        int c;
        while ((c = fgetc(f)) != EOF && checked < 512) {
            checked++;
            if (c == '\n' || c == '\t' || c == '\r') continue;
            if (!isprint((unsigned char)c)) { printable = 0; break; }
        }
        fclose(f);
        if (printable) return FT_SOURCE;
    }

    return FT_UNKNOWN;
}

/* ------------------------------------------------------------------ */
/* Copy the target file so the original is never touched               */
/* ------------------------------------------------------------------ */
static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[8192];
    size_t n;
    int ok = 1;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = 0; break; }
    }
    if (ferror(in)) ok = 0;

    /* fclose can still fail to flush buffered data to disk - check it. */
    if (fclose(out) != 0) ok = 0;
    fclose(in);
    return ok ? 0 : -1;
}

static int make_copy_path(const char *src, char *out, size_t outsz) {
    const char *base = strrchr(src, '/');
    base = base ? base + 1 : src;

    if (mkdir("voidbreaker_scans", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "voidbreaker: could not create voidbreaker_scans/ directory\n");
        return -1;
    }

    time_t t = time(NULL);
    int wrote = snprintf(out, outsz, "voidbreaker_scans/%ld_%s.copy", (long)t, base);
    if (wrote < 0 || (size_t)wrote >= outsz) {
        fprintf(stderr, "voidbreaker: file path too long to build a working copy path\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Source-code analyzer                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *pattern;
    const char *type;
    const char *risk;
    const char *explanation;
} VulnRule;

static const VulnRule C_RULES[] = {
    { "strcpy(",    "Buffer Overflow",     "HIGH",     "strcpy() does not bound-check the destination buffer." },
    { "strcat(",    "Buffer Overflow",     "HIGH",     "strcat() does not bound-check the destination buffer." },
    { "gets(",      "Buffer Overflow",     "CRITICAL", "gets() has no way to limit input length at all." },
    { "sprintf(",   "Buffer Overflow",     "MEDIUM",   "sprintf() can overflow the destination buffer; use snprintf()." },
    { "vsprintf(",  "Buffer Overflow",     "MEDIUM",   "vsprintf() has the same unbounded-write issue as sprintf()." },
    { "scanf(",     "Buffer Overflow",     "MEDIUM",   "scanf(\"%s\", ...) has no bound and can overflow stack buffers." },
    { "memcpy(",    "Memory Corruption",   "LOW",      "memcpy() with an attacker-influenced length can overflow the destination." },
    { "strtok(",    "Thread-Safety",       "LOW",      "strtok() uses shared static state; not reentrant/thread-safe (use strtok_r)." },
    { "alloca(",    "Stack Exhaustion",    "LOW",      "alloca() size should be validated; unchecked size can blow the stack." },
    { "system(",    "Command Injection",   "HIGH",     "system() with any non-constant input risks shell command injection." },
    { "popen(",     "Command Injection",   "HIGH",     "popen() with non-constant input risks shell command injection." },
    { "strncpy(",   "Unterminated String", "LOW",      "strncpy() may not NUL-terminate if src is as long as n." },
    { "rand(",      "Weak Randomness",     "LOW",      "rand() is not cryptographically secure; don't use it for tokens/keys." },
    { "srand(",     "Weak Randomness",     "LOW",      "srand() seed (e.g. time()) is often predictable, making rand() output guessable." },
    { "tmpnam(",    "Insecure Temp File",  "MEDIUM",   "tmpnam() is subject to race conditions (TOCTOU); use mkstemp()." },
    { "mktemp(",    "Insecure Temp File",  "MEDIUM",   "mktemp() is subject to race conditions (TOCTOU); use mkstemp()." },
};
#define NUM_C_RULES (sizeof(C_RULES) / sizeof(C_RULES[0]))

static const VulnRule PY_RULES[] = {
    { "eval(",          "Code Injection",     "CRITICAL", "eval() executes arbitrary Python from a string - never feed it untrusted input." },
    { "exec(",          "Code Injection",     "CRITICAL", "exec() executes arbitrary Python from a string - same risk as eval()." },
    { "os.system(",     "Command Injection",  "HIGH",     "os.system() runs a shell command; unsafe with unsanitized input." },
    { "os.popen(",      "Command Injection",  "HIGH",     "os.popen() runs a shell command; unsafe with unsanitized input." },
    { "shell=True",     "Command Injection",  "HIGH",     "subprocess call with shell=True is vulnerable to shell injection." },
    { "pickle.loads(",  "Insecure Deserialization", "CRITICAL", "Unpickling untrusted data can execute arbitrary code." },
    { "yaml.load(",     "Insecure Deserialization", "HIGH", "yaml.load() without SafeLoader can instantiate arbitrary objects." },
    { "marshal.loads(", "Insecure Deserialization", "HIGH", "marshal.loads() on untrusted data is unsafe (same class of bug as pickle)." },
    { "__import__(",    "Code Injection",     "MEDIUM",   "Dynamic __import__() with variable input can load arbitrary modules." },
    { "input(",         "Unvalidated Input",  "LOW",      "Input read here should be validated before use in sensitive operations." },
};
#define NUM_PY_RULES (sizeof(PY_RULES) / sizeof(PY_RULES[0]))

static const VulnRule JS_RULES[] = {
    { "eval(",                   "Code Injection",  "CRITICAL", "eval() executes arbitrary JS - never feed it untrusted input." },
    { "new Function(",           "Code Injection",  "CRITICAL", "new Function(...) compiles a string as code, similar risk to eval()." },
    { "child_process.exec(",     "Command Injection","HIGH",    "child_process.exec() runs a shell command; prefer execFile() with fixed args." },
    { "document.write(",         "XSS",             "MEDIUM",   "document.write() with unsanitized input enables cross-site scripting." },
    { ".innerHTML",              "XSS",             "MEDIUM",   "Assigning to innerHTML with unsanitized input enables XSS." },
    { "dangerouslySetInnerHTML", "XSS",             "MEDIUM",   "React's dangerouslySetInnerHTML bypasses XSS protection - sanitize input." },
    { "require(" ,               "Dynamic Require",  "LOW",     "require() with a variable path can be abused to load unexpected modules." },
};
#define NUM_JS_RULES (sizeof(JS_RULES) / sizeof(JS_RULES[0]))

static const VulnRule PHP_RULES[] = {
    { "eval(",         "Code Injection",    "CRITICAL", "eval() executes arbitrary PHP from a string." },
    { "system(",       "Command Injection", "HIGH",     "system() runs a shell command; unsafe with unsanitized input." },
    { "exec(",         "Command Injection", "HIGH",     "exec() runs a shell command; unsafe with unsanitized input." },
    { "shell_exec(",   "Command Injection", "HIGH",     "shell_exec() runs a shell command; unsafe with unsanitized input." },
    { "passthru(",     "Command Injection", "HIGH",     "passthru() runs a shell command; unsafe with unsanitized input." },
    { "unserialize(",  "Insecure Deserialization", "CRITICAL", "unserialize() on untrusted data can trigger object injection / RCE." },
    { "include($",     "Local File Inclusion", "HIGH",  "Dynamic include() with a variable path risks local/remote file inclusion." },
    { "require($",     "Local File Inclusion", "HIGH",  "Dynamic require() with a variable path risks local/remote file inclusion." },
    { "md5(",          "Weak Hash",         "LOW",      "md5() is broken for security purposes (password hashing, integrity checks)." },
    { "extract(",      "Variable Injection","MEDIUM",   "extract() on untrusted arrays can overwrite arbitrary local variables." },
};
#define NUM_PHP_RULES (sizeof(PHP_RULES) / sizeof(PHP_RULES[0]))

static const VulnRule JAVA_RULES[] = {
    { "Runtime.getRuntime().exec(", "Command Injection",       "HIGH",     "Runtime.exec() with unsanitized input risks command injection." },
    { "ProcessBuilder(",            "Command Injection",       "MEDIUM",   "ProcessBuilder with unsanitized arguments risks command injection." },
    { "readObject(",                "Insecure Deserialization","CRITICAL", "Java deserialization of untrusted streams is a classic RCE vector." },
    { "Class.forName(",             "Reflection Risk",         "LOW",      "Dynamic class loading from untrusted input can load unexpected code." },
    { "MessageDigest.getInstance(\"MD5\")", "Weak Hash",        "LOW",      "MD5 is broken for security purposes." },
    { "Cipher.getInstance(\"DES",   "Weak Crypto",              "MEDIUM",   "DES is an outdated, weak cipher - use AES instead." },
};
#define NUM_JAVA_RULES (sizeof(JAVA_RULES) / sizeof(JAVA_RULES[0]))

static const VulnRule GO_RULES[] = {
    { "exec.Command(",   "Command Injection", "HIGH", "exec.Command() with unsanitized input risks command injection." },
    { "unsafe.Pointer",  "Memory Safety",      "MEDIUM","unsafe.Pointer bypasses Go's memory safety guarantees - review carefully." },
    { "md5.New(",        "Weak Hash",          "LOW",   "MD5 is broken for security purposes." },
    { "html/template",   "Template Safety",    "LOW",   "Ensure you're using html/template (auto-escaping), not text/template, for HTML output." },
};
#define NUM_GO_RULES (sizeof(GO_RULES) / sizeof(GO_RULES[0]))

static const VulnRule RUBY_RULES[] = {
    { "eval(",         "Code Injection",           "CRITICAL", "eval() executes arbitrary Ruby from a string." },
    { "system(",       "Command Injection",        "HIGH",     "system() runs a shell command; unsafe with unsanitized input." },
    { "`",             "Command Injection",        "HIGH",     "Backtick execution runs a shell command; unsafe with unsanitized input." },
    { "Marshal.load(", "Insecure Deserialization", "CRITICAL", "Marshal.load() on untrusted data can execute arbitrary code." },
    { "YAML.load(",    "Insecure Deserialization", "HIGH",     "YAML.load() on untrusted data can instantiate arbitrary objects (use safe_load)." },
};
#define NUM_RUBY_RULES (sizeof(RUBY_RULES) / sizeof(RUBY_RULES[0]))

static const VulnRule SH_RULES[] = {
    { "eval ",        "Code Injection",    "HIGH",   "eval in a shell script executes its argument as a command - risky with variables." },
    { "| sh",         "Remote Code Exec",  "CRITICAL","Piping output straight into a shell executes unreviewed code." },
    { "| bash",       "Remote Code Exec",  "CRITICAL","Piping output straight into a shell executes unreviewed code." },
    { "chmod 777",    "Insecure Permissions","MEDIUM","chmod 777 grants world read/write/execute - almost always too permissive." },
    { "rm -rf $",     "Destructive Command","HIGH",   "rm -rf on an unquoted/unchecked variable can delete unintended paths." },
};
#define NUM_SH_RULES (sizeof(SH_RULES) / sizeof(SH_RULES[0]))

static const VulnRule RUST_RULES[] = {
    { "unsafe {",      "Memory Safety",     "MEDIUM", "unsafe block bypasses Rust's safety guarantees - review carefully." },
    { "transmute(",    "Memory Safety",     "HIGH",   "mem::transmute can violate type/memory safety if used incorrectly." },
    { "Command::new(", "Command Injection", "MEDIUM", "Spawning a process - verify the command/args aren't attacker-controlled." },
    { ".unwrap()",     "Panic Risk",        "LOW",    "unwrap() panics on None/Err - risky on anything that can fail at runtime." },
    { "from_utf8_unchecked(", "Memory Safety", "MEDIUM", "Skips UTF-8 validation - undefined behavior on invalid input." },
};
#define NUM_RUST_RULES (sizeof(RUST_RULES) / sizeof(RUST_RULES[0]))

static const VulnRule KOTLIN_RULES[] = {
    { "Runtime.getRuntime().exec(", "Command Injection",        "HIGH",     "Runtime.exec() with unsanitized input risks command injection." },
    { "ProcessBuilder(",            "Command Injection",        "MEDIUM",   "ProcessBuilder with unsanitized arguments risks command injection." },
    { "readObject(",                "Insecure Deserialization", "CRITICAL", "Deserializing untrusted streams is a classic RCE vector." },
    { "MessageDigest.getInstance(\"MD5\")", "Weak Hash",         "LOW",      "MD5 is broken for security purposes." },
    { "javascript:",                "XSS",                      "MEDIUM",   "javascript: URI scheme usage can enable script injection in WebViews." },
};
#define NUM_KOTLIN_RULES (sizeof(KOTLIN_RULES) / sizeof(KOTLIN_RULES[0]))

/* Generic fallback for unrecognized extensions - the handful of patterns
 * that mean roughly the same dangerous thing in most C-family languages. */
static const VulnRule GENERIC_RULES[] = {
    { "eval(",     "Code Injection",    "HIGH", "eval-like constructs executing a string as code are risky with untrusted input." },
    { "system(",   "Command Injection", "HIGH", "Shelling out with unsanitized input risks command injection." },
    { "exec(",     "Command Injection", "HIGH", "Shelling out / dynamic execution with unsanitized input is risky." },
};
#define NUM_GENERIC_RULES (sizeof(GENERIC_RULES) / sizeof(GENERIC_RULES[0]))

/* Cross-language: scanned on EVERY source file regardless of detected
 * language, looking for hardcoded credentials and key material. */
static const VulnRule SECRET_RULES[] = {
    { "-----BEGIN RSA PRIVATE KEY-----",    "Hardcoded Secret", "CRITICAL", "An RSA private key appears to be embedded directly in this file." },
    { "-----BEGIN OPENSSH PRIVATE KEY-----","Hardcoded Secret", "CRITICAL", "An OpenSSH private key appears to be embedded directly in this file." },
    { "-----BEGIN PRIVATE KEY-----",        "Hardcoded Secret", "CRITICAL", "A private key appears to be embedded directly in this file." },
    { "AKIA",        "Hardcoded Secret", "CRITICAL", "Matches the AWS Access Key ID prefix - looks like a hardcoded AWS credential." },
    { "sk_live_",     "Hardcoded Secret", "CRITICAL", "Matches a Stripe LIVE secret key prefix - a real payment credential may be exposed." },
    { "ghp_",         "Hardcoded Secret", "HIGH",     "Matches a GitHub personal access token prefix." },
    { "xoxb-",        "Hardcoded Secret", "HIGH",     "Matches a Slack bot token prefix." },
    { "sk_test_",     "Hardcoded Secret", "MEDIUM",   "Matches a Stripe TEST secret key prefix - still shouldn't be committed to source." },
    { "api_key=",     "Hardcoded Secret", "MEDIUM",   "Possible hardcoded API key - verify this isn't a real credential." },
    { "apikey=",      "Hardcoded Secret", "MEDIUM",   "Possible hardcoded API key - verify this isn't a real credential." },
    { "secret_key=",  "Hardcoded Secret", "MEDIUM",   "Possible hardcoded secret key - verify this isn't a real credential." },
    { "password=",    "Hardcoded Secret", "MEDIUM",   "Possible hardcoded password - verify this isn't a real credential." },
    { "passwd=",      "Hardcoded Secret", "MEDIUM",   "Possible hardcoded password - verify this isn't a real credential." },
};
#define NUM_SECRET_RULES (sizeof(SECRET_RULES) / sizeof(SECRET_RULES[0]))

typedef struct {
    const VulnRule *rules;
    size_t count;
} RuleSet;

static RuleSet rules_for_language(Language lang) {
    switch (lang) {
        case LANG_C:    return (RuleSet){ C_RULES,       NUM_C_RULES };
        case LANG_PY:   return (RuleSet){ PY_RULES,      NUM_PY_RULES };
        case LANG_JS:   return (RuleSet){ JS_RULES,      NUM_JS_RULES };
        case LANG_PHP:  return (RuleSet){ PHP_RULES,     NUM_PHP_RULES };
        case LANG_JAVA: return (RuleSet){ JAVA_RULES,    NUM_JAVA_RULES };
        case LANG_GO:   return (RuleSet){ GO_RULES,      NUM_GO_RULES };
        case LANG_RUBY:   return (RuleSet){ RUBY_RULES,   NUM_RUBY_RULES };
        case LANG_SH:     return (RuleSet){ SH_RULES,     NUM_SH_RULES };
        case LANG_RUST:   return (RuleSet){ RUST_RULES,   NUM_RUST_RULES };
        case LANG_KOTLIN: return (RuleSet){ KOTLIN_RULES, NUM_KOTLIN_RULES };
        default:          return (RuleSet){ GENERIC_RULES, NUM_GENERIC_RULES };
    }
}

static int looks_like_format_string_bug(const char *line) {
    const char *funcs[] = { "printf(", "fprintf(", "syslog(" };
    for (size_t f = 0; f < sizeof(funcs)/sizeof(funcs[0]); f++) {
        long idx = asm_find_str(line, funcs[f]);
        if (idx < 0) continue;
        /* Require a word boundary before the match so "printf(" doesn't
         * also match inside "sprintf(" / "vsprintf(" / "snprintf(". */
        if (idx > 0) {
            char prev = line[idx - 1];
            if (isalnum((unsigned char)prev) || prev == '_') continue;
        }
        const char *after = line + idx + (long)strlen(funcs[f]);

        if (strcmp(funcs[f], "fprintf(") == 0) {
            const char *comma = strchr(after, ',');
            if (!comma) continue;
            after = comma + 1;
        }
        while (*after == ' ') after++;
        if (*after != '"' && *after != '\0') {
            return 1;
        }
    }
    return 0;
}

/* Detects lines that are themselves rule-table initializers, e.g.
 *     { "strcpy(",    "Buffer Overflow",     "HIGH", ... },
 * so that when VoidBreaker scans its own (or another analyzer's)
 * source, it doesn't flag the pattern strings inside its own rule
 * database as if they were real, executed calls. */
static int looks_like_rule_table_line(const char *line) {
    /* Matches both real initializer lines ( { "strcpy(", ... ) and the
     * same thing quoted inside a doc-comment example ( * { "strcpy(" ). */
    return asm_find_str(line, "{ \"") >= 0 || asm_find_str(line, "{\"") >= 0;
}

/* Skip comment lines entirely - documentation that quotes a dangerous
 * function name/pattern as an example isn't a real call to it. */
static int looks_like_comment_line(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] == '*') return 1;
    if (p[0] == '/' && (p[1] == '*' || p[1] == '/')) return 1;
    return 0;
}

/* Word-boundary-aware pattern match: stops "gets(" from matching inside
 * "fgets(", or "printf(" inside "sprintf(" (whichever has not already
 * been excluded by looks_like_rule_table_line / looks_like_comment_line). */
static int pattern_hits(const char *line, const char *pattern) {
    long idx = asm_find_str(line, pattern);
    if (idx < 0) return 0;
    if (idx > 0) {
        char prev = line[idx - 1];
        if (isalnum((unsigned char)prev) || prev == '_') return 0;
    }
    return 1;
}

static int analyze_source_file(const char *display_path, const char *scan_path, Language lang) {
    FILE *f = fopen(scan_path, "r");
    if (!f) {
        fprintf(stderr, "voidbreaker: could not open %s for reading\n", scan_path);
        return -1;
    }

    RuleSet rs = rules_for_language(lang);
    int run_format_check = (lang == LANG_C || lang == LANG_PHP);

    char line[4096];
    int lineno = 0;
    int findings = 0;
    Counts counts = {0};

    printf("[*] Source mode (%s): scanning %s\n\n", language_name(lang), display_path);

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        if (looks_like_rule_table_line(line) || looks_like_comment_line(line)) continue;

        for (size_t r = 0; r < rs.count; r++) {
            if (pattern_hits(line, rs.rules[r].pattern)) {
                printf("[!] %s:%d\n", display_path, lineno);
                printf("    Type   : %s\n", rs.rules[r].type);
                printf("    Risk   : %s%s%s\n", risk_color(rs.rules[r].risk), rs.rules[r].risk, C_RESET);
                printf("    Match  : %s\n", rs.rules[r].pattern);
                printf("    Why    : %s\n\n", rs.rules[r].explanation);
                findings++;
                count_risk(&counts, rs.rules[r].risk);
            }
        }

        /* Secrets/credentials are checked on every file, any language. */
        for (size_t r = 0; r < NUM_SECRET_RULES; r++) {
            if (pattern_hits(line, SECRET_RULES[r].pattern)) {
                printf("[!] %s:%d\n", display_path, lineno);
                printf("    Type   : %s\n", SECRET_RULES[r].type);
                printf("    Risk   : %s%s%s\n", risk_color(SECRET_RULES[r].risk), SECRET_RULES[r].risk, C_RESET);
                printf("    Match  : %s\n", SECRET_RULES[r].pattern);
                printf("    Why    : %s\n\n", SECRET_RULES[r].explanation);
                findings++;
                count_risk(&counts, SECRET_RULES[r].risk);
            }
        }

        if (run_format_check && looks_like_format_string_bug(line)) {
            printf("[!] %s:%d\n", display_path, lineno);
            printf("    Type   : Format String Bug\n");
            printf("    Risk   : %sHIGH%s\n", risk_color("HIGH"), C_RESET);
            printf("    Why    : printf-family call with a non-literal format argument.\n");
            printf("             If user input reaches the format string, %%x/%%n\n");
            printf("             specifiers allow arbitrary memory reads/writes.\n\n");
            findings++;
            count_risk(&counts, "HIGH");
        }
    }

    fclose(f);
    print_summary(&counts, findings);
    return findings;
}

/* ------------------------------------------------------------------ */
/* Binary analyzer                                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *symbol;
    const char *type;
    const char *risk;
    const char *explanation;
} AsmRule;

static const AsmRule ASM_RULES[] = {
    { "strcpy@plt",    "Buffer Overflow",     "HIGH",     "Call to strcpy - unbounded copy into destination buffer." },
    { "strcat@plt",    "Buffer Overflow",     "HIGH",     "Call to strcat - unbounded append into destination buffer." },
    { "gets@plt",      "Buffer Overflow",     "CRITICAL", "Call to gets - classic unbounded stdin read, easiest stack smash." },
    { "sprintf@plt",   "Buffer Overflow",     "MEDIUM",   "Call to sprintf - can overflow destination buffer." },
    { "vsprintf@plt",  "Buffer Overflow",     "MEDIUM",   "Call to vsprintf - same unbounded-write risk as sprintf." },
    { "scanf@plt",     "Buffer Overflow",     "MEDIUM",   "Call to scanf - %s without width limit can overflow a buffer." },
    { "sscanf@plt",    "Buffer Overflow",     "MEDIUM",   "Call to sscanf - %s without width limit can overflow a buffer." },
    { "memcpy@plt",    "Memory Corruption",   "LOW",      "Call to memcpy - review whether the length is attacker-influenced." },
    { "strtok@plt",    "Thread-Safety",       "LOW",      "Call to strtok - uses shared static state, not reentrant." },
    { "system@plt",    "Command Injection",   "HIGH",     "Call to system - risky if any argument is attacker-influenced." },
    { "popen@plt",     "Command Injection",   "HIGH",     "Call to popen - risky if any argument is attacker-influenced." },
    { "execve@plt",    "Command Execution",   "MEDIUM",   "Call to execve - review the argument/environment source." },
    { "execl@plt",     "Command Execution",   "MEDIUM",   "Call to execl - review the argument source." },
    { "execlp@plt",    "Command Execution",   "MEDIUM",   "Call to execlp - searches PATH, review the argument source." },
    { "execvp@plt",    "Command Execution",   "MEDIUM",   "Call to execvp - searches PATH, review the argument source." },
    { "rand@plt",      "Weak Randomness",     "LOW",      "Call to rand - not cryptographically secure; don't use for tokens/keys." },
    { "srand@plt",     "Weak Randomness",     "LOW",      "Call to srand - check the seed isn't predictable (e.g. time())." },
    { "tmpnam@plt",    "Insecure Temp File",  "MEDIUM",   "Call to tmpnam - race-condition prone (TOCTOU); prefer mkstemp." },
    { "mktemp@plt",    "Insecure Temp File",  "MEDIUM",   "Call to mktemp - race-condition prone (TOCTOU); prefer mkstemp." },
    { "setuid@plt",    "Privilege Handling",  "MEDIUM",   "Call to setuid - verify privileges are dropped in the correct order." },
    { "chmod@plt",     "Permissions",         "LOW",      "Call to chmod - verify the mode isn't overly permissive (e.g. 0777)." },
    { "strcpy_chk@plt","Buffer Overflow",     "LOW",      "Fortified strcpy (_FORTIFY_SOURCE) - safer, but confirm the bound is correct." },
};
#define NUM_ASM_RULES (sizeof(ASM_RULES) / sizeof(ASM_RULES[0]))

static void check_protections(const char *scan_path) {
    static char out[65536];
    char *path = (char *)scan_path; /* execvp wants char *const argv[], not const char *const */

    printf("[*] Hardening check (readelf):\n");

    {
        char *argv[] = { "readelf", "-d", path, NULL };
        if (exec_capture(argv, out, sizeof(out)) > 0) {
            if (asm_find_str(out, "BIND_NOW") >= 0)
                printf("    [+] RELRO       : Full (BIND_NOW present)\n");
            else
                printf("    [!] RELRO       : Partial/None (no BIND_NOW) - GOT is more writable\n");
        } else {
            printf("    [?] RELRO       : could not run readelf -d (is readelf installed?)\n");
        }
    }

    {
        char *argv[] = { "readelf", "-h", path, NULL };
        if (exec_capture(argv, out, sizeof(out)) > 0) {
            if (asm_find_str(out, "DYN (") >= 0)
                printf("    [+] PIE         : Enabled (ET_DYN)\n");
            else
                printf("    [!] PIE         : Disabled (ET_EXEC) - fixed load address aids exploitation\n");
        } else {
            printf("    [?] PIE         : could not run readelf -h (is readelf installed?)\n");
        }
    }

    {
        char *argv[] = { "readelf", "-lW", path, NULL };
        if (exec_capture(argv, out, sizeof(out)) > 0) {
            if (asm_find_str(out, "GNU_STACK") >= 0 && asm_find_str(out, "RWE") >= 0)
                printf("    [!] NX stack    : Disabled (stack is executable)\n");
            else
                printf("    [+] NX stack    : Enabled (stack is not executable)\n");
        } else {
            printf("    [?] NX stack    : could not run readelf -l (is readelf installed?)\n");
        }
    }

    {
        char *argv[] = { "readelf", "-sW", path, NULL };
        if (exec_capture(argv, out, sizeof(out)) > 0) {
            if (asm_find_str(out, "__stack_chk_fail") >= 0)
                printf("    [+] Canary      : Present (__stack_chk_fail referenced)\n");
            else
                printf("    [!] Canary      : Not found - stack smashing may go undetected\n");
        } else {
            printf("    [?] Canary      : could not run readelf -s (is readelf installed?)\n");
        }
    }

    printf("\n");
}

static int analyze_binary_file(const char *display_path, const char *scan_path) {
    char asm_path[1300];
    int wrote = snprintf(asm_path, sizeof(asm_path), "%s.asm", scan_path);
    if (wrote < 0 || (size_t)wrote >= sizeof(asm_path)) {
        fprintf(stderr, "voidbreaker: path too long to build .asm output path\n");
        return -1;
    }

    printf("[*] Binary mode: disassembling %s -> %s\n\n", display_path, asm_path);

    {
        char *path = (char *)scan_path;
        char *argv[] = { "objdump", "-d", "-M", "intel", path, NULL };
        if (exec_to_file(argv, asm_path) != 0) {
            fprintf(stderr, "voidbreaker: couldn't run objdump - is it installed and on PATH?\n");
            return -1;
        }
    }

    FILE *f = fopen(asm_path, "r");
    if (!f) {
        fprintf(stderr, "voidbreaker: could not open disassembly output %s\n", asm_path);
        return -1;
    }

    check_protections(scan_path);

    char line[2048];
    int lineno = 0, findings = 0;
    Counts counts = {0};

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        for (size_t r = 0; r < NUM_ASM_RULES; r++) {
            if (asm_find_str(line, ASM_RULES[r].symbol) >= 0) {
                printf("[!] %s:%d (disassembly)\n", asm_path, lineno);
                printf("    Type   : %s\n", ASM_RULES[r].type);
                printf("    Risk   : %s%s%s\n", risk_color(ASM_RULES[r].risk), ASM_RULES[r].risk, C_RESET);
                printf("    Instr  : %s", line);
                printf("    Why    : %s\n\n", ASM_RULES[r].explanation);
                findings++;
                count_risk(&counts, ASM_RULES[r].risk);
            }
        }
    }
    fclose(f);

    /* Also scan the binary's extracted printable strings for hardcoded
     * secrets/credentials - these never show up in the disassembly text. */
    {
        char *path = (char *)scan_path;
        char *argv[] = { "strings", "-n", "6", path, NULL };
        ExecStream es;
        if (exec_popen_r(argv, &es) == 0) {
            char sline[2048];
            int sidx = 0;
            while (fgets(sline, sizeof(sline), es.f)) {
                sidx++;
                for (size_t r = 0; r < NUM_SECRET_RULES; r++) {
                    if (pattern_hits(sline, SECRET_RULES[r].pattern)) {
                        printf("[!] %s (strings, entry %d)\n", display_path, sidx);
                        printf("    Type   : %s\n", SECRET_RULES[r].type);
                        printf("    Risk   : %s%s%s\n", risk_color(SECRET_RULES[r].risk), SECRET_RULES[r].risk, C_RESET);
                        printf("    Match  : %s\n", SECRET_RULES[r].pattern);
                        printf("    Why    : %s\n\n", SECRET_RULES[r].explanation);
                        findings++;
                        count_risk(&counts, SECRET_RULES[r].risk);
                    }
                }
            }
            exec_popen_close(&es);
        } else {
            printf("[*] Note: could not run 'strings' - skipping secret scan of binary strings.\n\n");
        }
    }

    printf("[*] Full disassembly saved to %s\n", asm_path);
    print_summary(&counts, findings);
    return findings;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    print_banner();

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file-to-scan>\n", argv[0]);
        fprintf(stderr, "  Accepts C/C++ source files or compiled binaries (ELF, .o, PE .exe).\n");
        return 1;
    }

    const char *target = argv[1];
    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "voidbreaker: cannot access '%s'\n", target);
        return 1;
    }

    FileType type = detect_file_type(target);

    char copy_path[600];
    if (make_copy_path(target, copy_path, sizeof(copy_path)) != 0) {
        return 1;
    }
    if (copy_file(target, copy_path) != 0) {
        fprintf(stderr, "voidbreaker: failed to make a working copy of '%s'\n", target);
        return 1;
    }
    printf("[*] Working on a copy: %s (original untouched)\n\n", copy_path);

    int findings;
    switch (type) {
        case FT_SOURCE: {
            Language lang = detect_language(target);
            findings = analyze_source_file(target, copy_path, lang);
            break;
        }
        case FT_ELF:
        case FT_PE:
            findings = analyze_binary_file(target, copy_path);
            break;
        default:
            fprintf(stderr, "voidbreaker: could not determine file type of '%s'\n", target);
            findings = -1;
            break;
    }

    return findings < 0 ? 1 : 0;
}
