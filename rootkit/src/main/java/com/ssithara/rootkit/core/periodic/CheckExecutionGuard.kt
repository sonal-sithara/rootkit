package com.ssithara.rootkit.core.periodic

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Guard to prevent overlapping check executions.
 *
 * When a check is already in progress, new check requests are skipped
 * to prevent resource buildup and ensure predictable performance.
 */
internal class CheckExecutionGuard {

    private val checkMutex = Mutex()
    private val isCheckInProgress = AtomicBoolean(false)

    /**
     * Execute a check cycle with overlap protection.
     *
     * @param block The check cycle to execute
     * @return true if the check was executed, false if skipped due to overlap
     */
    suspend fun <T> executeWithGuard(block: suspend () -> T): Result<T> {
        if (!isCheckInProgress.compareAndSet(false, true)) {
            // Previous check still running, skip this cycle
            return Result.skipped()
        }

        return try {
            checkMutex.withLock {
                Result.executed(block())
            }
        } finally {
            isCheckInProgress.set(false)
        }
    }

    /**
     * Check if a check is currently in progress
     */
    fun isInProgress(): Boolean = isCheckInProgress.get()

    /**
     * Result of an execution attempt
     */
    sealed class Result<out T> {
        data class Executed<T>(val value: T) : Result<T>()
        data object Skipped : Result<Nothing>()

        companion object {
            fun <T> executed(value: T): Result<T> = Executed(value)
            fun <T> skipped(): Result<T> = Skipped
        }

        fun isExecuted(): Boolean = this is Executed
        fun isSkipped(): Boolean = this is Skipped

        inline fun <R> fold(
            onExecuted: (T) -> R,
            onSkipped: () -> R
        ): R = when (this) {
            is Executed -> onExecuted(value)
            is Skipped -> onSkipped()
        }
    }
}
