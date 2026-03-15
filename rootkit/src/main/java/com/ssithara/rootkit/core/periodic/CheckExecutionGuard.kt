package com.ssithara.rootkit.core.periodic

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Guard to prevent overlapping check executions.
 *
 * When a check is already in progress, new check requests are skipped
 * to prevent resource buildup and ensure predictable performance.
 *
 * Uses a Mutex with tryLock() to provide atomic check-and-acquire semantics,
 * avoiding TOCTOU (time-of-check-time-of-use) vulnerabilities.
 */
internal class CheckExecutionGuard {

    private val checkMutex = Mutex()

    /**
     * Execute a check cycle with overlap protection.
     *
     * Uses tryLock() to atomically attempt to acquire the lock, preventing
     * race conditions that would occur with separate check-then-acquire logic.
     *
     * @param block The check cycle to execute
     * @return true if the check was executed, false if skipped due to overlap
     */
    suspend fun <T> executeWithGuard(block: suspend () -> T): Result<T> {
        // Try to acquire the lock atomically - this prevents TOCTOU vulnerability
        // that would exist if we checked a separate flag before acquiring the lock
        if (!checkMutex.tryLock()) {
            // Previous check still running, skip this cycle
            return Result.skipped()
        }

        return try {
            Result.executed(block())
        } finally {
            checkMutex.unlock()
        }
    }

    /**
     * Check if a check is currently in progress.
     *
     * Note: This provides a best-effort check. For synchronization purposes,
     * use executeWithGuard() which provides atomic acquire-and-execute semantics.
     */
    fun isInProgress(): Boolean = checkMutex.isLocked

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
