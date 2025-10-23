#include <jni.h>
#include <string>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// Check for Frida libraries in `/proc/self/maps`
bool checkFridaLibraries() {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) return false;

    std::string line;
    std::vector<std::string> fridaLibs = {"frida-agent", "frida-gadget", "frida"};

    while (getline(mapsFile, line)) {
        for (const auto &lib: fridaLibs) {
            if (line.find(lib) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

// Check if a port is in use (Frida default ports: 27042, 27043)
bool isPortInUse(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");

    bool inUse = connect(sock, (struct sockaddr *) &address, sizeof(address)) == 0;
    close(sock);
    return inUse;
}

// Check for suspicious files
bool checkSuspiciousFiles() {
    std::vector<std::string> suspiciousFiles = {
            "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/", "/system/xbin/daemonsu",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"
    };

    for (const auto &filePath: suspiciousFiles) {
        if (access(filePath.c_str(), F_OK) == 0) {
            return true;
        }
    }
    return false;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_core_ssithara_rootkit_HookDetection_nativeDetectHook(JNIEnv *env, jobject thiz) {
    return checkFridaLibraries() || isPortInUse(27042) || checkSuspiciousFiles();
}



