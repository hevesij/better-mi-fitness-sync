package com.bettermifitness.sync.data.preferences

import com.mifitness.miclient.auth.MiCredentials
import kotlinx.coroutines.flow.Flow

/** ISP: auth token + credentials used by sync policy. */
interface CredentialsPort {
    val token: Flow<String?>
    suspend fun loadCredentials(): MiCredentials?
    suspend fun saveCredentials(credentials: MiCredentials)
}

/** ISP: sync settings + last-run outcome persistence. */
interface SyncPreferencesPort {
    val autoSync: Flow<Boolean>
    val enabledMetrics: Flow<Set<String>>
    val syncRangeDays: Flow<Int>
    suspend fun updateLastSync(timestamp: String)
    suspend fun updateLastBackgroundSync(timestamp: String)
    suspend fun updateLastSyncOutcome(status: String, message: String?)
    suspend fun updateLastBackgroundSyncOutcome(status: String, message: String?)
}

/**
 * Single hot snapshot of user sync preferences.
 * [ready] is false until the first DataStore emission lands; screens must hold a
 * skeleton until then instead of rendering zero-metric placeholders.
 */
data class UserPrefsSnapshot(
    val ready: Boolean = false,
    val enabledMetrics: Set<String> = emptySet(),
    val syncRangeDays: Int = 7,
    val autoSync: Boolean = false,
    val lastSyncTime: String? = null,
    val lastBackgroundSyncTime: String? = null,
)

/** ISP: ensure Mi API session is usable. */
interface SyncSessionPort {
    suspend fun ensureActive(): Boolean
}
