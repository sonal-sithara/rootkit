/**
 * @file memory_tampering_detection.cpp
 * @brief Native memory tampering detection methods.
 * 
 * Detects memory-based tampering and code injection:
 * - Suspicious memory region detection
 * - Anonymous executable memory detection
 * - Code integrity verification
 * - Unusual permission detection
 * - Code cave detection
 * - ASLR bypass detection
 */

#include <jni.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <dirent.h>
#include <link.h>
#include <elf.h>
#include <malloc.h>
#include <sys/mman.h>

/**
 * @brief Check for suspicious memory regions that could indicate tampering.
 * 
 * Looks for anonymous executable memory regions.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if suspicious regions detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_detectSuspiciousRegions(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    int suspicious_count = 0;

    while (fgets(line, sizeof(line), fp) != nullptr) {
        char perms[5];
        unsigned long start, end;

        // Parse the line
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
            // Check for writable and executable memory
            bool is_writable = (perms[1] == 'w');
            bool is_executable = (perms[2] == 'x');
            bool is_readonly = (perms[0] == 'r');
            (void) is_readonly;  // Reserved for future use
            (void) start;  // Reserved for future use
            (void) end;  // Reserved for future use

            // Check if it's an anonymous mapping (no path at end)
            bool is_anonymous = false;
            if (strstr(line, ".so") == nullptr &&
                strstr(line, ".apk") == nullptr &&
                strstr(line, ".dex") == nullptr &&
                strstr(line, ".jar") == nullptr &&
                strstr(line, "/system") == nullptr &&
                strstr(line, "/vendor") == nullptr &&
                strstr(line, "/data/app") == nullptr &&
                strstr(line, "[") == nullptr) {
                is_anonymous = true;
            }

            // Suspicious: writable + executable + anonymous
            if (is_writable && is_executable && is_anonymous) {
                suspicious_count++;
            }
        }
    }

    fclose(fp);

    // More than a threshold of suspicious regions indicates tampering
    return suspicious_count > 2 ? JNI_TRUE : JNI_FALSE;
}

/**
 * @brief Check for anonymous executable memory regions.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if anonymous executable memory detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_detectAnonymousExecMemory(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fp) != nullptr) {
        char perms[5];
        unsigned long start, end;

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
            (void) start;  // Reserved for future use
            (void) end;  // Reserved for future use

            // Check for executable permission
            bool is_executable = (perms[2] == 'x');

            // Check if it's anonymous (empty pathname or just whitespace after inode)
            // Anonymous mappings have no file backing
            bool is_anonymous = true;

            // Look for file path indicators
            const char *ptr = line;
            int space_count = 0;
            while (*ptr != '\0') {
                if (*ptr == ' ') {
                    space_count++;
                    // After 5 spaces, we should have the pathname
                    if (space_count >= 5) {
                        ptr++;
                        // Skip whitespace
                        while (*ptr == ' ') ptr++;
                        // Check if there's a path
                        if (*ptr != '\0' && *ptr != '\n') {
                            // Check if it's a special region
                            if (strstr(ptr, "[heap]") != nullptr ||
                                strstr(ptr, "[stack]") != nullptr ||
                                strstr(ptr, "[vdso]") != nullptr ||
                                strstr(ptr, "[vvar]") != nullptr ||
                                strstr(ptr, "/") != nullptr) {
                                is_anonymous = false;
                            }
                        }
                        break;
                    }
                }
                ptr++;
            }

            if (is_executable && is_anonymous) {
                // Check for rwx permission (highly suspicious)
                if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                    fclose(fp);
                    return JNI_TRUE;
                }
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Check for code integrity by verifying memory protections.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if code integrity violation detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_checkCodeIntegrity(JNIEnv *env,
                                                                                        jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    int modified_regions = 0;

    while (fgets(line, sizeof(line), fp) != nullptr) {
        // Check for our own library
        if (strstr(line, "librootkit.so") != nullptr) {
            char perms[5];
            if (sscanf(line, "%*s %4s", perms) == 1) {
                // Our library should not be writable
                if (perms[1] == 'w') {
                    modified_regions++;
                }
            }
        }

        // Check for system libraries that shouldn't be writable
        if (strstr(line, "/system/lib") != nullptr ||
            strstr(line, "/system/lib64") != nullptr ||
            strstr(line, "/apex/com.android") != nullptr) {
            char perms[5];
            if (sscanf(line, "%*s %4s", perms) == 1) {
                // System libraries should not be writable
                if (perms[1] == 'w') {
                    modified_regions++;
                }
            }
        }
    }

    fclose(fp);
    return modified_regions > 0 ? JNI_TRUE : JNI_FALSE;
}

/**
 * @brief Check for memory regions with unusual permissions.
 * 
 * Detects violations of W^X (write xor execute) policy.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if unusual permissions detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_detectUnusualPermissions(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fp) != nullptr) {
        char perms[5];
        if (sscanf(line, "%*s %4s", perms) == 1) {
            // Check for write+execute permission on any region
            // This is suspicious as modern systems use W^X
            if (perms[1] == 'w' && perms[2] == 'x') {
                // Exclude legitimate cases like JIT compilers
                if (strstr(line, "jit") == nullptr &&
                    strstr(line, "art") == nullptr &&
                    strstr(line, "oat") == nullptr &&
                    strstr(line, "odex") == nullptr &&
                    strstr(line, "dex2oat") == nullptr &&
                    strstr(line, "[heap]") == nullptr &&
                    strstr(line, "webview") == nullptr &&
                    strstr(line, "chrome") == nullptr &&
                    strstr(line, "[anon:dalvik") == nullptr &&
                    strstr(line, "[anon:art") == nullptr) {
                    fclose(fp);
                    return JNI_TRUE;
                }
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Check for potential code caves in memory.
 * 
 * Code caves are unused regions that could be used for injection.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if suspicious code caves detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_detectCodeCaves(JNIEnv *env,
                                                                                     jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    unsigned long prev_end = 0;
    int large_gaps = 0;

    while (fgets(line, sizeof(line), fp) != nullptr) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            // Check for unusually large gaps between memory regions
            if (prev_end > 0 && start > prev_end) {
                unsigned long gap = start - prev_end;
                // Gap larger than 1MB is suspicious
                if (gap > 1024 * 1024) {
                    large_gaps++;
                }
            }
            prev_end = end;
        }
    }

    fclose(fp);
    return large_gaps > 3 ? JNI_TRUE : JNI_FALSE;
}

/**
 * @brief Check for modified base addresses (ASLR bypass detection).
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if potential ASLR bypass detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_MemoryTamperingDetection_detectModifiedBaseAddress(
        JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    // Get the base address of our library
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    uintptr_t lowest_addr = UINTPTR_MAX;
    bool found_lib = false;

    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, "librootkit.so") != nullptr) {
            unsigned long start;
            if (sscanf(line, "%lx", &start) == 1) {
                if (start < lowest_addr) {
                    lowest_addr = start;
                    found_lib = true;
                }
            }
        }
    }

    fclose(fp);

    if (!found_lib) {
        return JNI_FALSE;
    }

    // Check if the address looks suspiciously low (potential ASLR bypass)
    // On 64-bit Android, libraries are typically loaded at high addresses
    // This is a heuristic check
    if (lowest_addr < 0x10000) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}
