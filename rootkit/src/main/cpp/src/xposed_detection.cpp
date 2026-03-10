/**
 * @file xposed_detection.cpp
 * @brief Native Xposed framework detection methods.
 * 
 * Detects Xposed framework and related hooking mechanisms:
 * - Memory map analysis for Xposed signatures
 * - Loaded library detection
 * - Zygote process modification detection
 * - Riru and Zygisk framework detection
 * - Hook memory region analysis
 */

#include <jni.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <dirent.h>

// Xposed signatures in memory maps
static const char *XPOSED_SIGNATURES[] = {
        "libxposed_art.so",
        "libedxposed.so",
        "liblsposed.so",
        "libriru_xposed",
        "xposed",
        "XposedBridge",
        "de.robv.android.xposed",
        "io.github.lsposed",
        "EdXposed-Bridge",
        "libepic.so",
        "libriru.so",
        "libxposed_loader.so"
};

/**
 * @brief Detect Xposed by checking /proc/self/maps for Xposed signatures.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Xposed signature found in memory maps, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectByMemoryMaps(JNIEnv *env,
                                                                               jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    int num_sigs = sizeof(XPOSED_SIGNATURES) / sizeof(XPOSED_SIGNATURES[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_sigs; i++) {
            if (strstr(line, XPOSED_SIGNATURES[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Detect Xposed by checking loaded libraries.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Xposed library detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectByLibraries(JNIEnv *env,
                                                                              jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *xposed_libs[] = {
            "libxposed_art.so",
            "libedxposed.so",
            "liblsposed.so",
            "libxposed_loader.so",
            "libepic.so",
            "libriru.so",
            "libriru_xposed.so"
    };
    int num_libs = sizeof(xposed_libs) / sizeof(xposed_libs[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_libs; i++) {
            if (strstr(line, xposed_libs[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Detect Xposed by checking for Zygote process modifications.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Zygote modification detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectByZygote(JNIEnv *env,
                                                                           jclass clazz) {
    (void) env;
    (void) clazz;

    // Check for Zygote-related Xposed traces
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *zygote_sigs[] = {
            "XposedZygote",
            "xposed_zygote",
            "libxposed_zygote"
    };

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < 3; i++) {
            if (strstr(line, zygote_sigs[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Detect Riru framework (used by many Xposed implementations).
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Riru detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectRiru(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    // Check for Riru by looking at memory maps
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *riru_sigs[] = {
            "libriru.so",
            "riru-core",
            "libriru_"
    };
    int num_sigs = sizeof(riru_sigs) / sizeof(riru_sigs[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_sigs; i++) {
            if (strstr(line, riru_sigs[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);

    // Also check for Riru directory
    if (access("/data/adb/riru", F_OK) == 0) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/**
 * @brief Detect Zygisk (Magisk's Zygote injection mechanism).
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Zygisk detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectZygisk(JNIEnv *env,
                                                                         jclass clazz) {
    (void) env;
    (void) clazz;

    // Check for Zygisk in memory maps
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *zygisk_sigs[] = {
            "libzygisk.so",
            "zygisk",
            "zygisk_"
    };
    int num_sigs = sizeof(zygisk_sigs) / sizeof(zygisk_sigs[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_sigs; i++) {
            if (strstr(line, zygisk_sigs[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);

    // Check for Zygisk directory
    if (access("/data/adb/zygisk", F_OK) == 0) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/**
 * @brief Check for hook-related memory regions.
 * 
 * Xposed frameworks often create anonymous memory regions for hooks.
 * Looks for suspicious anonymous memory regions with rwx permissions.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if suspicious hook memory detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_XposedDetection_detectHookMemory(JNIEnv *env,
                                                                             jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];

    // Look for suspicious anonymous memory regions with rwx permissions
    while (fgets(line, sizeof(line), fp) != nullptr) {
        // Check for rwx permissions on anonymous mappings
        // Format: address perms offset dev inode pathname
        char perms[5];
        if (sscanf(line, "%*s %4s", perms) == 1) {
            // Check for writable and executable anonymous memory
            if (perms[1] == 'w' && perms[2] == 'x') {
                // Check if it's anonymous (no pathname)
                if (strstr(line, "[") == nullptr ||
                    strstr(line, "[heap]") != nullptr ||
                    strstr(line, "[anon:dalvik") != nullptr ||
                    strstr(line, "[anon:art") != nullptr ||
                    strstr(line, "jit") != nullptr ||
                    strstr(line, "oat") != nullptr) {
                    // Legitimate JIT or heap memory - not a hook
                    continue;
                }
                // This could be a hook region
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}
