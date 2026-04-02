/**
 * @file native_hook_detection.cpp
 * @brief Native hook detection methods for function hooking frameworks.
 * 
 * Detects various native hooking techniques:
 * - Inline hooks (function prologue modification)
 * - GOT (Global Offset Table) hooks
 * - PLT (Procedure Linkage Table) hooks
 * - Hook framework detection
 * - Modified function pointer detection
 * 
 * Architecture support: ARM64, ARM32, x86_64, x86
 */

#include <jni.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <link.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <vector>

/**
 * @brief Represents a single parsed line from /proc/self/maps.
 *
 * Storing the full original line alongside start/end lets callers reuse the
 * same strstr checks that the original per-entry code used, without reopening
 * the file on every iteration.
 */
struct MapEntry {
    uintptr_t start;
    uintptr_t end;
    char line[1024];
};

/**
 * @brief Parse /proc/self/maps into a vector of MapEntry values.
 *
 * Opens the file exactly once and returns all entries so that callers can do
 * O(n) address lookups without repeated file I/O inside hot loops.
 *
 * @return Vector of parsed map entries (empty if the file cannot be opened).
 */
static std::vector<MapEntry> parse_proc_maps() {
    std::vector<MapEntry> entries;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return entries;
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        MapEntry e = {};
        unsigned long start_ul, end_ul;
        if (sscanf(buf, "%lx-%lx", &start_ul, &end_ul) == 2) {
            e.start = (uintptr_t) start_ul;
            e.end   = (uintptr_t) end_ul;
            strncpy(e.line, buf, sizeof(e.line) - 1);
            e.line[sizeof(e.line) - 1] = '\0';
            entries.push_back(e);
        }
    }

    fclose(fp);
    return entries;
}

/**
 * @brief Get the base address of a library.
 *
 * @param lib_name Name of the library to find
 * @return Base address of the library, or 0 if not found
 */
static uintptr_t get_library_base(const char *lib_name) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return 0;
    }

    char line[1024];
    uintptr_t base_addr = 0;

    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, lib_name) != nullptr) {
            unsigned long addr_temp;
            if (sscanf(line, "%lx", &addr_temp) == 1) {
                base_addr = (uintptr_t) addr_temp;
                break;
            }
        }
    }

    fclose(fp);
    return base_addr;
}

/**
 * @brief Detect inline hooks by checking function prologues.
 * 
 * Architecture-specific patterns for x86, x86_64, ARM32, and ARM64.
 * Checks for common hook patterns like JMP, BR, and trampoline instructions.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if inline hook detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_NativeHookDetection_detectInlineHooks(JNIEnv *env,
                                                                                  jclass clazz) {
    (void) env;
    (void) clazz;

    const char *functions_to_check[] = {
            "open",
            "read",
            "write",
            "connect",
            "fopen"
    };

    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (libc_handle == nullptr) {
        return JNI_FALSE;
    }

    bool detected = false;

    auto maps = parse_proc_maps();

    for (int i = 0; i < 5 && !detected; i++) {
        void *func_ptr = dlsym(libc_handle, functions_to_check[i]);
        if (func_ptr != nullptr) {
            // Verify the function address is in a readable memory region
            uintptr_t func_addr = (uintptr_t)func_ptr;
            bool readable = false;
            for (const auto &entry : maps) {
                if (func_addr >= entry.start && func_addr < entry.end) {
                    readable = (entry.line[0] != '\0'); // valid entry found
                    break;
                }
            }
            if (!readable) continue;

#if defined(__aarch64__)
            // ARM64 detection
            // Check for BR instruction (unconditional branch to register)
            // BR Xn = 0xD61F0000 | (n << 5)
            uint32_t *arm_bytes = (uint32_t *)func_ptr;
            uint32_t instr = *arm_bytes;

            // Check for BR instruction (unconditional branch to register)
            if ((instr & 0xFFFFFC1F) == 0xD61F0000) {
                detected = true;
                break;
            }

            // Check for LDR + BR pattern (common in ARM64 hooks)
            // LDR X16, [PC, #offset] followed by BR X16
            if ((instr & 0xFF000000) == 0x58000000) {
                uint32_t next_instr = *(arm_bytes + 1);
                if ((next_instr & 0xFFFFFC1F) == 0xD61F0000) {
                    detected = true;
                    break;
                }
            }

#elif defined(__arm__)
            // ARM32 detection
            // Check for BX instruction (branch and exchange)
            // BX Rn = 0xE12FFF10 | (n)
            uint32_t *arm_bytes = (uint32_t *)func_ptr;
            uint32_t instr = *arm_bytes;

            // Check for BX instruction (mask out register number in lower nibble)
            if ((instr & 0xFFFFFFF0) == 0xE12FFF10) {
                detected = true;
                break;
            }

            // Check for LDR PC, [PC, #offset] pattern (ARM32 hook)
            // LDR (literal) to PC
            if ((instr & 0x0F00F000) == 0x0100F000) {
                detected = true;
                break;
            }

            // Check for Thumb mode: MOV PC, Rn pattern
            // This is another common ARM32 hook pattern
            if ((instr & 0xFFFFFF00) == 0xE1A0F000) {
                detected = true;
                break;
            }

#elif defined(__x86_64__)
            // x86_64 detection
            unsigned char *bytes = (unsigned char *)func_ptr;
            // Check for JMP instruction (0xE9)
            if (bytes[0] == 0xE9) {
                detected = true;
                break;
            }

            // Check for MOV RAX + JMP RAX pattern
            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
                detected = true;
                break;
            }

#elif defined(__i386__)
            // x86 (32-bit) detection
            unsigned char *bytes = (unsigned char *) func_ptr;
            // Check for JMP instruction (0xE9)
            if (bytes[0] == 0xE9) {
                detected = true;
                break;
            }

            // Check for PUSH + RET pattern (common x86 hook)
            if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
                detected = true;
                break;
            }

            // Check for MOV EAX + JMP EAX pattern
            if (bytes[0] == 0xB8 && bytes[5] == 0xFF && bytes[6] == 0xE0) {
                detected = true;
                break;
            }
#else
            // Fallback: Check for common hook patterns across architectures
            // This is less precise but provides basic coverage
            unsigned char *bytes = (unsigned char *)func_ptr;

            // Check for x86/x86_64 JMP instruction (0xE9)
            if (bytes[0] == 0xE9) {
                detected = true;
                break;
            }

            // Check for ARM BR instruction pattern (first 4 bytes)
            uint32_t *word_ptr = (uint32_t *)func_ptr;
            if ((word_ptr[0] & 0xFFFFFC1F) == 0xD61F0000) {
                detected = true;
                break;
            }
#endif
        }
    }

    dlclose(libc_handle);
    return detected ? JNI_TRUE : JNI_FALSE;
}

/**
 * @brief Detect GOT (Global Offset Table) hooks.
 * 
 * GOT hooks redirect function pointers in the GOT.
 * Architecture-specific implementation for 32-bit and 64-bit ELF.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if GOT hook detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_NativeHookDetection_detectGOTHooks(JNIEnv *env,
                                                                               jclass clazz) {
    (void) env;
    (void) clazz;

    // Get base address of our library
    uintptr_t lib_base = get_library_base("librootkit.so");
    if (lib_base == 0) {
        return JNI_FALSE;
    }

    // Check ELF class to determine 32-bit or 64-bit
    unsigned char *elf_ident = (unsigned char *) lib_base;

    // Verify ELF magic
    if (memcmp(elf_ident, ELFMAG, SELFMAG) != 0) {
        return JNI_FALSE;
    }

#if defined(__aarch64__) || defined(__x86_64__)
    // 64-bit ELF parsing
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)lib_base;

    // Validate ELF header fields before use
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256) {
        return JNI_FALSE;
    }

    // Find the dynamic section
    Elf64_Phdr *phdr = (Elf64_Phdr *)(lib_base + ehdr->e_phoff);
    Elf64_Dyn *dyn = nullptr;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn *)(lib_base + phdr[i].p_vaddr);
            break;
        }
    }

    if (dyn == nullptr) {
        return JNI_FALSE;
    }

    // Find GOT and symbol table
    Elf64_Sym *symtab = nullptr;
    char *strtab = nullptr;
    Elf64_Rela *rela = nullptr;
    size_t rela_count = 0;
    
    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                symtab = (Elf64_Sym *)(lib_base + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (char *)(lib_base + d->d_un.d_ptr);
                break;
            case DT_RELA:
                rela = (Elf64_Rela *)(lib_base + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                rela_count = d->d_un.d_val / sizeof(Elf64_Rela);
                break;
        }
    }
    
    if (symtab == nullptr || strtab == nullptr || rela == nullptr) {
        return JNI_FALSE;
    }

    // Parse /proc/self/maps once before the loop so we do not pay the cost of
    // opening and reading the entire file for every relocation entry.
    auto maps = parse_proc_maps();

    // Check each relocation entry
    for (size_t i = 0; i < rela_count; i++) {
        uint32_t reloc_type = ELF64_R_TYPE(rela[i].r_info);
        
        // Check for JMP_SLOT relocation (function pointer)
        // Use architecture-specific relocation type
#if defined(__aarch64__)
        if (reloc_type == R_AARCH64_JUMP_SLOT) {
#elif defined(__x86_64__)
        if (reloc_type == R_X86_64_JUMP_SLOT) {
#else
        if (reloc_type == R_AARCH64_JUMP_SLOT) {  // Fallback
#endif
            // Get the address where the function pointer is stored
            void **got_entry = (void **)(lib_base + rela[i].r_offset);
            
            // Get the symbol name
            size_t sym_idx = ELF64_R_SYM(rela[i].r_info);
            const char *sym_name = strtab + symtab[sym_idx].st_name;
            (void)sym_name;  // Reserved for future use
            
            // Check if the GOT entry points outside legitimate libraries
            uintptr_t addr = (uintptr_t)*got_entry;
            
            if (addr != 0) {
                for (const auto &entry : maps) {
                    if (addr >= entry.start && addr < entry.end) {
                        // Check if it's in a legitimate library
                        if (strstr(entry.line, ".so") != nullptr ||
                            strstr(entry.line, "/system") != nullptr ||
                            strstr(entry.line, "/apex") != nullptr) {
                            break;
                        }
                        // Address is in mapped region but not a legitimate library
                        return JNI_TRUE;
                    }
                }
            }
        }
    }

#else
    // 32-bit ELF parsing (ARM32, x86)
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) lib_base;

    // Validate ELF header fields before use
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256) {
        return JNI_FALSE;
    }

    // Find the dynamic section
    Elf32_Phdr *phdr = (Elf32_Phdr *) (lib_base + ehdr->e_phoff);
    Elf32_Dyn *dyn = nullptr;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf32_Dyn *) (lib_base + phdr[i].p_vaddr);
            break;
        }
    }

    if (dyn == nullptr) {
        return JNI_FALSE;
    }

    // Find GOT and symbol table
    Elf32_Sym *symtab = nullptr;
    char *strtab = nullptr;
    Elf32_Rel *rel = nullptr;
    size_t rel_count = 0;

    for (Elf32_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                symtab = (Elf32_Sym *) (lib_base + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (char *) (lib_base + d->d_un.d_ptr);
                break;
            case DT_REL:
                rel = (Elf32_Rel *) (lib_base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                break;
        }
    }

    if (symtab == nullptr || strtab == nullptr || rel == nullptr) {
        return JNI_FALSE;
    }

    // Parse /proc/self/maps once before the loop (same as 64-bit path above).
    auto maps = parse_proc_maps();

    // Check each relocation entry
    for (size_t i = 0; i < rel_count; i++) {
        uint32_t reloc_type = ELF32_R_TYPE(rel[i].r_info);

        // Check for JMP_SLOT relocation (function pointer)
        // Use architecture-specific relocation type
#if defined(__arm__)
        if (reloc_type == R_ARM_JUMP_SLOT) {
#elif defined(__i386__)
        if (reloc_type == R_386_JMP_SLOT) {
#else
            if (reloc_type == R_ARM_JUMP_SLOT) {  // Fallback for unknown 32-bit
#endif
            // Get the address where the function pointer is stored
            void **got_entry = (void **) (lib_base + rel[i].r_offset);

            // Get the symbol name
            size_t sym_idx = ELF32_R_SYM(rel[i].r_info);
            const char *sym_name = strtab + symtab[sym_idx].st_name;
            (void) sym_name;  // Reserved for future use

            // Check if the GOT entry points outside legitimate libraries
            uintptr_t addr = (uintptr_t) *got_entry;

            if (addr != 0) {
                for (const auto &entry : maps) {
                    if (addr >= entry.start && addr < entry.end) {
                        // Check if it's in a legitimate library
                        if (strstr(entry.line, ".so") != nullptr ||
                            strstr(entry.line, "/system") != nullptr ||
                            strstr(entry.line, "/apex") != nullptr) {
                            break;
                        }
                        // Address is in mapped region but not a legitimate library
                        return JNI_TRUE;
                    }
                }
            }
        }
    }

#endif

    return JNI_FALSE;
}

/**
 * @brief Detect PLT (Procedure Linkage Table) hooks.
 * 
 * PLT hooks modify the PLT to redirect function calls.
 * Architecture-specific implementation for 32-bit and 64-bit ELF.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if PLT hook detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_NativeHookDetection_detectPLTHooks(JNIEnv *env,
                                                                               jclass clazz) {
    (void) env;
    (void) clazz;

    uintptr_t lib_base = get_library_base("librootkit.so");
    if (lib_base == 0) {
        return JNI_FALSE;
    }

    // Check ELF class to determine 32-bit or 64-bit
    unsigned char *elf_ident = (unsigned char *) lib_base;

    // Verify ELF magic
    if (memcmp(elf_ident, ELFMAG, SELFMAG) != 0) {
        return JNI_FALSE;
    }

#if defined(__aarch64__) || defined(__x86_64__)
    // 64-bit ELF parsing
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)lib_base;

    // Validate ELF header fields before use
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256) {
        return JNI_FALSE;
    }

    // Find PLT section
    Elf64_Phdr *phdr = (Elf64_Phdr *)(lib_base + ehdr->e_phoff);
    uintptr_t plt_start = 0;
    uintptr_t plt_end = 0;
    
    // Look for PLT in program headers
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            // PLT is usually in the first executable LOAD segment
            if (phdr[i].p_flags & PF_X) {
                if (plt_start == 0) {
                    plt_start = lib_base + phdr[i].p_vaddr;
                    plt_end = plt_start + phdr[i].p_memsz;
                }
            }
        }
    }
    
    if (plt_start == 0) {
        return JNI_FALSE;
    }
    
    // Check PLT entries for modifications
    // PLT entries should follow a specific pattern
    // On ARM64: STP + ADRP + LDR + BR
    
    uint32_t *plt_ptr = (uint32_t *)plt_start;
    int suspicious_count = 0;
    
    // Sample some PLT entries
    for (int i = 0; i < 20 && (uintptr_t)plt_ptr < plt_end; i++) {
        uint32_t instr = *plt_ptr;
        
#if defined(__aarch64__)
        // Check for unexpected BR instructions at the start
        // Normal PLT entry starts with STP, not BR
        if ((instr & 0xFFFFFC1F) == 0xD61F0000) {
            suspicious_count++;
        }
#elif defined(__x86_64__)
        // Check for unexpected JMP instructions
        // Normal PLT entry starts with JMP to GOT, but hooked entries may differ
        if ((instr & 0xFF) == 0xE9 || (instr & 0xFF) == 0xEB) {
            suspicious_count++;
        }
#endif
        
        // Move to next PLT entry (typically 16 bytes on ARM64, variable on x86_64)
        plt_ptr += 4;
    }

#else
    // 32-bit ELF parsing (ARM32, x86)
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) lib_base;

    // Validate ELF header fields before use
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256) {
        return JNI_FALSE;
    }

    // Find PLT section
    Elf32_Phdr *phdr = (Elf32_Phdr *) (lib_base + ehdr->e_phoff);
    uintptr_t plt_start = 0;
    uintptr_t plt_end = 0;

    // Look for PLT in program headers
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            // PLT is usually in the first executable LOAD segment
            if (phdr[i].p_flags & PF_X) {
                if (plt_start == 0) {
                    plt_start = lib_base + phdr[i].p_vaddr;
                    plt_end = plt_start + phdr[i].p_memsz;
                }
            }
        }
    }

    if (plt_start == 0) {
        return JNI_FALSE;
    }

    // Check PLT entries for modifications
    uint32_t *plt_ptr = (uint32_t *) plt_start;
    int suspicious_count = 0;

    // Sample some PLT entries
    for (int i = 0; i < 20 && (uintptr_t) plt_ptr < plt_end; i++) {
        uint32_t instr = *plt_ptr;

#if defined(__arm__)
        // Check for unexpected BX/BLX instructions at the start
        // Normal PLT entry has specific pattern, hooked entries may have branch
        // Mask out register number in lower nibble
        if ((instr & 0xFFFFFFF0) == 0xE12FFF10 ||  // BX
            (instr & 0xFFFFFFF0) == 0xE12FFF30) {  // BLX
            suspicious_count++;
        }
#elif defined(__i386__)
        // Check for unexpected JMP instructions
        if ((instr & 0xFF) == 0xE9 || (instr & 0xFF) == 0xEB) {
            suspicious_count++;
        }
#endif

        // Move to next PLT entry (typically 16 bytes on ARM32, 16 bytes on x86)
        plt_ptr += 4;
    }

#endif

    return suspicious_count > 2 ? JNI_TRUE : JNI_FALSE;
}

/**
 * @brief Check for hooking frameworks by examining memory regions.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if hook framework detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_NativeHookDetection_detectHookFrameworks(JNIEnv *env,
                                                                                     jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *hook_frameworks[] = {
            "libsubstrate.so",
            "libcydia.so",
            "libfrida",
            "libxposed",
            "libedxposed",
            "liblsposed",
            "libepic.so",
            "libdexposed.so",
            "libwhale.so",
            "libAnd64InlineHook.so"
    };
    int num_frameworks = sizeof(hook_frameworks) / sizeof(hook_frameworks[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_frameworks; i++) {
            if (strstr(line, hook_frameworks[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Check for modified function pointers in critical structures.
 * 
 * Heuristic check for modified function pointers by verifying that
 * critical libc functions point to expected locations.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if modified function pointer detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jint JNICALL
Java_com_ssithara_rootkit_detection_runtime_NativeHookDetection_detectModifiedFunctionPointers(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    // This is a heuristic check for modified function pointers
    // We check if certain standard library functions point to expected locations
    // Returns: 1 = detected, 0 = not detected, -1 = detection failure

    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (libc_handle == nullptr) {
        return -1;
    }

    // Get the base address of libc
    uintptr_t libc_base = get_library_base("libc.so");

    // Check a few critical functions
    const char *critical_funcs[] = {
            "open",
            "read",
            "write",
            "connect"
    };
    int num_funcs = sizeof(critical_funcs) / sizeof(critical_funcs[0]);

    for (int i = 0; i < num_funcs; i++) {
        void *func = dlsym(libc_handle, critical_funcs[i]);
        if (func != nullptr) {
            // Check if function is within libc's memory range
            uintptr_t func_addr = (uintptr_t) func;

            // libc functions should be within a reasonable range of libc base
            // This is a simplified heuristic
            if (libc_base > 0 && func_addr > 0) {
                // Function should be within ~10MB of libc base
                if (func_addr < libc_base || func_addr > libc_base + (10 * 1024 * 1024)) {
                    dlclose(libc_handle);
                    return 1;
                }
            }
        }
    }

    dlclose(libc_handle);
    return 0;
}
