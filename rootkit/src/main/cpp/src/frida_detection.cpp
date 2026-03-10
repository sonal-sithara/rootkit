/**
 * @file frida_detection.cpp
 * @brief Native Frida framework detection methods.
 * 
 * Detects Frida instrumentation framework through various techniques:
 * - Port scanning for Frida server
 * - Memory map analysis for Frida signatures
 * - Thread name inspection
 * - Loaded library detection
 * - File descriptor analysis
 * - Environment variable checks
 */

#include <jni.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Frida default ports to check
static const int FRIDA_PORTS[] = {27042};

// Frida signatures in memory maps
static const char *FRIDA_SIGNATURES[] = {
        "frida-agent",
        "frida-gadget",
        "frida-server",
        "linjector",
        "re.frida.server",
        "frida-agent-64",
        "frida-agent-32",
        "libfrida-gadget.so"
};

// Frida thread names
static const char *FRIDA_THREADS[] = {
        "frida:rpc",
        "frida:main",
        "gmain",
        "gum-js-loop",
        "gum-js-engine",
        "pool-frida",
        "pool-spawner"
};

/**
 * @brief Detect Frida by checking common ports.
 * 
 * Frida server typically listens on 127.0.0.1:27042.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida port is open, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByPorts(JNIEnv *env,
                                                                         jclass clazz) {
    (void) env;
    (void) clazz;

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &sa.sin_addr);

    int num_ports = sizeof(FRIDA_PORTS) / sizeof(FRIDA_PORTS[0]);

    for (int i = 0; i < num_ports; i++) {
        sa.sin_port = htons(FRIDA_PORTS[i]);
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock >= 0) {
            // Set timeout for connect
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000; // 100ms timeout
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == 0) {
                close(sock);
                return JNI_TRUE;
            }
            close(sock);
        }
    }

    return JNI_FALSE;
}

/**
 * @brief Detect Frida by checking /proc/self/maps for Frida signatures.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida signature found in memory maps, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByMemoryMaps(JNIEnv *env,
                                                                              jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    int num_sigs = sizeof(FRIDA_SIGNATURES) / sizeof(FRIDA_SIGNATURES[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_sigs; i++) {
            if (strstr(line, FRIDA_SIGNATURES[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Detect Frida by checking thread names.
 * 
 * Frida creates threads with specific names like "frida:rpc", "gmain", etc.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida thread name detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByThreads(JNIEnv *env,
                                                                           jclass clazz) {
    (void) env;
    (void) clazz;

    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir == nullptr) {
        return JNI_FALSE;
    }

    struct dirent *entry;
    int num_threads = sizeof(FRIDA_THREADS) / sizeof(FRIDA_THREADS[0]);

    while ((entry = readdir(task_dir)) != nullptr) {
        // Skip . and ..
        if (entry->d_name[0] == '.') {
            continue;
        }

        char comm_path[512];
        snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);

        FILE *comm_file = fopen(comm_path, "r");
        if (comm_file != nullptr) {
            char comm[256];
            if (fgets(comm, sizeof(comm), comm_file) != nullptr) {
                // Remove trailing newline
                comm[strcspn(comm, "\n")] = 0;

                for (int i = 0; i < num_threads; i++) {
                    if (strstr(comm, FRIDA_THREADS[i]) != nullptr) {
                        fclose(comm_file);
                        closedir(task_dir);
                        return JNI_TRUE;
                    }
                }
            }
            fclose(comm_file);
        }
    }

    closedir(task_dir);
    return JNI_FALSE;
}

/**
 * @brief Detect Frida by checking loaded libraries.
 * 
 * Similar to memory maps detection but specifically looks for .so files.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida library detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByLibraries(JNIEnv *env,
                                                                             jclass clazz) {
    (void) env;
    (void) clazz;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return JNI_FALSE;
    }

    char line[1024];
    const char *frida_libs[] = {
            "libfrida-gadget.so",
            "frida-agent-64.so",
            "frida-agent-32.so",
            "frida-gadget-64.so",
            "frida-gadget-32.so"
    };
    int num_libs = sizeof(frida_libs) / sizeof(frida_libs[0]);

    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (int i = 0; i < num_libs; i++) {
            if (strstr(line, frida_libs[i]) != nullptr) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
    }

    fclose(fp);
    return JNI_FALSE;
}

/**
 * @brief Detect Frida by checking for specific file descriptors.
 * 
 * Frida creates named pipes that can be detected through /proc/self/fd.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida file descriptor detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByFileDescriptors(JNIEnv *env,
                                                                                   jclass clazz) {
    (void) env;
    (void) clazz;

    DIR *fd_dir = opendir("/proc/self/fd");
    if (fd_dir == nullptr) {
        return JNI_FALSE;
    }

    struct dirent *entry;

    while ((entry = readdir(fd_dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char fd_link[512];
        char fd_target[512];
        snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%s", entry->d_name);

        ssize_t len = readlink(fd_link, fd_target, sizeof(fd_target) - 1);
        if (len > 0) {
            fd_target[len] = '\0';

            // Check for Frida-related file descriptors
            if (strstr(fd_target, "frida") != nullptr ||
                strstr(fd_target, "linjector") != nullptr ||
                strstr(fd_target, "re.frida") != nullptr) {
                closedir(fd_dir);
                return JNI_TRUE;
            }
        }
    }

    closedir(fd_dir);
    return JNI_FALSE;
}

/**
 * @brief Detect Frida by checking for specific environment variables.
 * 
 * @param env JNI environment (unused)
 * @param clazz Java class reference (unused)
 * @return JNI_TRUE if Frida environment variable detected, JNI_FALSE otherwise
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_runtime_FridaDetection_detectByEnvVars(JNIEnv *env,
                                                                           jclass clazz) {
    (void) env;
    (void) clazz;

    // Check for common Frida environment variables
    const char *frida_env_vars[] = {
            "FRIDA_SCRIPT_PATH",
            "FRIDA_EXTERNAL_DEVICE",
            "FRIDA_SERVER_PATH"
    };

    int num_vars = sizeof(frida_env_vars) / sizeof(frida_env_vars[0]);
    for (int i = 0; i < num_vars; i++) {
        if (getenv(frida_env_vars[i]) != nullptr) {
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}
