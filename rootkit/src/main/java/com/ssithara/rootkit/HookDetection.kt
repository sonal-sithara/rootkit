package com.ssithara.rootkit

class HookDetection {

    companion object {
        @JvmStatic
        private external fun checkFridaByPort(): Boolean

        fun isFridaDetected(): Boolean {
            return checkFridaByPort()
        }
    }

}