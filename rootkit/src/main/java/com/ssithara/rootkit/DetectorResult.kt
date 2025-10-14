package com.ssithara.rootkit;

import android.content.Context

abstract class DetectorResult(protected val context: Context) {

    enum class Result {
        NOT_FOUND, FOUND
    }

    abstract fun run(): Result
}
