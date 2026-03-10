package com.ssithara.rootkit.core

import android.content.Context

abstract class DetectorResult(protected val context: Context) {

    abstract fun run(): Result
}
