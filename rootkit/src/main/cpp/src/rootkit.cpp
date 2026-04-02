#include <jni.h>
#include <unistd.h>
#include <cstdio>
#include <malloc.h>
#include <android/log.h>
#include <fcntl.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>
#include <sys/ptrace.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>


static inline bool is_mountpaths_detected();

static inline bool is_supath_detected();

static const char *TAG = "DetectMagiskNative";
static const char *blacklistedMountPaths[] = {
        "magisk",
        "core/mirror",
        "core/img"

};


/*static const char *suPaths[] = {
        "/sbin/magisk",
        "/sbin/.magisk",
        "/sbin/magisk32",
        "/sbin/magisk64",
        "/sbin/magiskinit",
        "/sbin/magiskpolicy",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/bin/su",
        "/system/bin/.ext/su",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/system/xbin/su",
        "/cache/su",
        "/cache/magisk",
        "/cache/.magisk",
        "/debug_ramdisk/magisk",
        "/debug_ramdisk/su",
        "/cache/Magisk",
        "/data/su",
        "/dev/su",
        "/data/adb/magisk",
        "/data/adb/.magisk",
        "/data/adb/magisk/busybox",
        "/data/adb/.magisk/busybox",
        "/system/xbin/daemonsu",
        "/data/adb/magisk.img",
        "/data/adb/magisk",
        "/data/adb/.magisk",
        "/data/magisk",
        "/data/zygisk",
        "/sbin/zygisk",
        "/sbin/supolicy",
        "/data/local/tmp/frida-gadget",

};*/

static const char *suPaths[] = {
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/bin/su",
        "/system/bin/.ext/su",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/system/xbin/su",
        "/cache/su",
        "/data/su",
        "/dev/su"
};


__attribute__((always_inline))
static inline bool is_mountpaths_detected() {
    int len = sizeof(blacklistedMountPaths) / sizeof(blacklistedMountPaths[0]);
    bool bRet = false;

    FILE *fp = fopen("/proc/self/mounts", "r");
    if (fp == nullptr)
        return false;

    std::string content;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        content.append(buf);
    }

    fclose(fp);

    for (int i = 0; i < len; i++) {
        if (content.find(blacklistedMountPaths[i]) != std::string::npos) {
            bRet = true;
            break;
        }
    }
    return bRet;
}


__attribute__((always_inline))
static inline bool is_supath_detected() {
    int len = sizeof(suPaths) / sizeof(suPaths[0]);

    bool bRet = false;
    for (int i = 0; i < len; i++) {
        //__android_log_print(ANDROID_LOG_INFO, TAG, "Checking SU Path  :%s", suPaths[i]);
        if (open(suPaths[i], O_RDONLY) >= 0) {
            // __android_log_print(ANDROID_LOG_INFO, TAG, "Found SU Path :%s", suPaths[i]);
            bRet = true;
            break;
        }
        if (0 == access(suPaths[i], R_OK)) {
            //__android_log_print(ANDROID_LOG_INFO, TAG, "Found SU Path :%s", suPaths[i]);
            bRet = true;
            break;
        }
    }

    return bRet;
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ssithara_rootkit_detection_root_MagiskDetection_isMagiskPresentNative(JNIEnv *env,
                                                                               jobject thiz) {
    bool bRet = false;
    do {
        bRet = is_supath_detected();
        if (bRet)
            break;
        bRet = is_mountpaths_detected();
        if (bRet)
            break;
    } while (false);

    if (bRet)
        return true;
    else
        return false;
}