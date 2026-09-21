package com.bettermifitness.sync.data.repository

import com.bettermifitness.sync.data.MiSessionManager
import com.bettermifitness.sync.data.SessionRefreshResult
import com.bettermifitness.sync.data.api.HeartRateEntry
import com.bettermifitness.sync.data.api.FitnessResponse
import com.bettermifitness.sync.data.api.SleepEntry
import com.bettermifitness.sync.data.api.WeightMeasurement
import com.bettermifitness.sync.data.api.WorkoutSession
import com.bettermifitness.sync.data.parse.MiFitnessParsers
import com.bettermifitness.sync.data.parse.toRaw
import com.bettermifitness.sync.data.preferences.SyncPreferences
import com.bettermifitness.sync.health.HealthDataNormalizer
import com.bettermifitness.sync.health.HealthStore
import com.bettermifitness.sync.health.HealthTimePolicy
import com.mifitness.miclient.api.MiApiException
import kotlin.time.Clock
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit

data class SyncProgress(
    val heartRate: SyncState = SyncState.Idle,
    val restingHeartRate: SyncState = SyncState.Idle,
    val sleep: SyncState = SyncState.Idle,
    val hrv: SyncState = SyncState.Idle,
    val steps: SyncState = SyncState.Idle,
    val distance: SyncState = SyncState.Idle,
    val activeCalories: SyncState = SyncState.Idle,
    val spo2: SyncState = SyncState.Idle,
    val weight: SyncState = SyncState.Idle,
    val workouts: SyncState = SyncState.Idle,
    val bloodPressure: SyncState = SyncState.Idle,
    val temperature: SyncState = SyncState.Idle,
    val vo2Max: SyncState = SyncState.Idle,
)

sealed class SyncState {
    data object Idle : SyncState()
    data object InProgress : SyncState()
    data class Success(val count: Int) : SyncState()
    data class Error(val message: String) : SyncState()
}

/**
 * Orchestrates Mi fetch → parse → platform health write.
 * Each metric fails independently; one bad metric does not abort the rest.
 * On [MiApiException.AuthExpired], attempts a single passToken refresh for the whole run.
 *
 * Weight is bidirectional latest-only (sparse weigh-ins) — newest timestamp wins
 * regardless of sync window. Body-fat rides with weight when present but is not
 * a separate bidirectional metric (Mi has no standalone body-fat input). Other metrics remain window-based.
 */
class HealthRepository(
    private val session: MiSessionManager,
    private val healthWriter: HealthStore,
) : HealthSyncRunner {
    private val _syncProgress = MutableStateFlow(SyncProgress())
    override val syncProgress: StateFlow<SyncProgress> = _syncProgress.asStateFlow()
    private val api get() = session.api

    private var authRefreshTried = false
    private var sawAuthFailure = false
    private var lastRefreshUserMessage: String? = null
    private var lastRefreshRetryable: Boolean = false
    private val retryableFailures = mutableListOf<Boolean>()
    private val stateMutex = Mutex()
    // Bound concurrent Mi requests so parallel metrics cannot trigger rate limits.
    private val fetchSemaphore = Semaphore(MAX_CONCURRENT_FETCHES)

    override suspend fun syncAll(
        from: String,
        to: String,
        enabled: Set<String>,
    ): SyncRunResult {
        authRefreshTried = false
        sawAuthFailure = false
        lastRefreshUserMessage = null
        lastRefreshRetryable = false
        retryableFailures.clear()
        _syncProgress.value = SyncProgress()

        supervisorScope {
            val resting = if ("resting_heart_rate" in enabled) {
                async { syncRestingHeartRate(from, to) }
            } else null
            // Sleep rows are fetched once and shared with HRV (derived from sleep payloads).
            val sleepRows = if ("sleep" in enabled || "hrv" in enabled) {
                async {
                    fetchSemaphore.withPermit { api.getLatest("sleep", limit = 30) }
                }
            } else null
            // Steps rows are fetched once and shared with distance (same minute stream).
            val stepsRows = if ("steps" in enabled || "distance" in enabled) {
                async {
                    fetchSemaphore.withPermit { fetchAllByTime("steps", from, to) }
                }
            } else null
            // HR rows are fetched once and shared with workout enrichment.
            val hrRows = if ("heart_rate" in enabled || "workouts" in enabled) {
                async {
                    fetchSemaphore.withPermit {
                        try {
                            fetchAllByTime("heart_rate", from, to)
                        } catch (_: Exception) {
                            emptyList()
                        }
                    }
                }
            } else null
            val heartRate = if ("heart_rate" in enabled) {
                async { syncHeartRate(hrRows!!) }
            } else null
            val sleep = if ("sleep" in enabled) {
                async { syncSleep(sleepRows!!) }
            } else null
            // HRV is derived from sleep payloads (no separate Mi key); empty = non-capable device.
            val hrv = if ("hrv" in enabled) {
                async { syncHrv(sleepRows!!) }
            } else null
            val steps = if ("steps" in enabled) {
                async { syncSteps(stepsRows!!) }
            } else null
            val distance = if ("distance" in enabled) {
                async { syncDistance(stepsRows!!) }
            } else null
            val calories = if ("active_calories" in enabled) {
                async { syncActiveCalories(from, to) }
            } else null
            val spo2 = if ("spo2" in enabled) {
                async { syncSpO2(from, to) }
            } else null
            val weight = if ("weight" in enabled) {
                async { syncWeightBidirectional() }
            } else null
            val workouts = if ("workouts" in enabled) {
                async { syncWorkouts(from, to, hrRows!!) }
            } else null
            val bloodPressure = if ("blood_pressure" in enabled) {
                async { syncBloodPressure(from, to) }
            } else null
            val temperature = if ("temperature" in enabled) {
                async { syncTemperature(from, to) }
            } else null
            val vo2Max = if ("vo2_max" in enabled) {
                async { syncVo2Max(from, to) }
            } else null
            listOfNotNull(
                resting,
                heartRate,
                sleep,
                hrv,
                steps,
                distance,
                calories,
                spo2,
                weight,
                workouts,
                bloodPressure,
                temperature,
                vo2Max,
            ).forEach { it.await() }
            sleepRows?.await()
            stepsRows?.await()
            hrRows?.await()
        }

        return SyncRunResult.from(
            progress = _syncProgress.value,
            metricKeys = enabled,
            retryableFlags = retryableFailures.toList(),
            authFailure = sawAuthFailure,
        )
    }

    suspend fun syncRestingHeartRate(from: String, to: String) {
        runMetric("restingHeartRate") {
            val response = fetchSemaphore.withPermit { api.getLatest("resting_heart_rate", limit = 30) }
            val samples = MiFitnessParsers.parseRestingHeartRateSamples(
                response.result?.dataList.orEmpty().map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeRestingHeartRate(samples)
            samples.size
        }
    }

    suspend fun syncHeartRate(from: String, to: String) {
        runMetric("heartRate") {
            val samples = MiFitnessParsers.parseHeartRateSamples(
                fetchAllByTime("heart_rate", from, to).map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeHeartRate(samples)
            samples.size
        }
    }

    private suspend fun syncHeartRate(
        hrRows: kotlinx.coroutines.Deferred<List<HeartRateEntry>>,
    ) {
        runMetric("heartRate") {
            val samples = MiFitnessParsers.parseHeartRateSamples(
                hrRows.await().map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeHeartRate(samples)
            samples.size
        }
    }

    suspend fun syncSleep(from: String, to: String) {
        runMetric("sleep") {
            val response = api.getLatest("sleep", limit = 30)
            val sessions = MiFitnessParsers.parseSleepSessions(
                response.result?.dataList.orEmpty().map { it.toRaw() },
            )
            if (sessions.isNotEmpty()) healthWriter.writeSleep(sessions)
            sessions.size
        }
    }

    private suspend fun syncSleep(
        sleepRows: kotlinx.coroutines.Deferred<FitnessResponse<SleepEntry>>,
    ) {
        runMetric("sleep") {
            val sessions = MiFitnessParsers.parseSleepSessions(
                sleepRows.await().result?.dataList.orEmpty().map { it.toRaw() },
            )
            if (sessions.isNotEmpty()) healthWriter.writeSleep(sessions)
            sessions.size
        }
    }

    /**
     * Overnight HRV from sleep JSON (`avg_hrv`). Uses the same `sleep` cloud key —
     * devices without HRV simply yield 0 samples (success).
     */
    suspend fun syncHrv(from: String, to: String) {
        runMetric("hrv") {
            val response = api.getLatest("sleep", limit = 30)
            val samples = MiFitnessParsers.parseHrvSamples(
                response.result?.dataList.orEmpty().map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeHrv(samples)
            samples.size
        }
    }

    private suspend fun syncHrv(
        sleepRows: kotlinx.coroutines.Deferred<FitnessResponse<SleepEntry>>,
    ) {
        runMetric("hrv") {
            val samples = MiFitnessParsers.parseHrvSamples(
                sleepRows.await().result?.dataList.orEmpty().map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeHrv(samples)
            samples.size
        }
    }

    suspend fun syncSteps(from: String, to: String) {
        runMetric("steps") {
            val records = MiFitnessParsers.parseHourlySteps(
                fetchAllByTime("steps", from, to).map { it.toRaw() },
            )
            if (records.isNotEmpty()) healthWriter.writeSteps(records)
            records.size
        }
    }

    private suspend fun syncSteps(
        stepsRows: kotlinx.coroutines.Deferred<List<HeartRateEntry>>,
    ) {
        runMetric("steps") {
            val records = MiFitnessParsers.parseHourlySteps(
                stepsRows.await().map { it.toRaw() },
            )
            if (records.isNotEmpty()) healthWriter.writeSteps(records)
            records.size
        }
    }

    suspend fun syncDistance(from: String, to: String) {
        runMetric("distance") {
            // Distance is embedded on the steps minute stream (bridge parity).
            val samples = MiFitnessParsers.parseHourlyDistanceFromSteps(
                fetchAllByTime("steps", from, to).map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeDistance(samples)
            samples.size
        }
    }

    private suspend fun syncDistance(
        stepsRows: kotlinx.coroutines.Deferred<List<HeartRateEntry>>,
    ) {
        runMetric("distance") {
            // Distance is embedded on the steps minute stream (bridge parity).
            val samples = MiFitnessParsers.parseHourlyDistanceFromSteps(
                stepsRows.await().map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeDistance(samples)
            samples.size
        }
    }

    private suspend fun syncActiveCalories(from: String, to: String) {
        runMetric("activeCalories") {
            val samples = MiFitnessParsers.parseHourlyActiveCalories(
                fetchSemaphore.withPermit { fetchAllByTime("calories", from, to) }
                    .map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeActiveCalories(samples)
            samples.size
        }
    }

    suspend fun syncSpO2(from: String, to: String) {
        runMetric("spo2") {
            val samples = MiFitnessParsers.parseSpO2Samples(
                fetchSemaphore.withPermit { fetchAllByTime("spo2", from, to) }
                    .map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeSpO2(samples)
            samples.size
        }
    }

    private suspend fun syncWeightBidirectional() {
        runMetric("weight") {
            val miLatest = getMiLatestWeight()
            val hcLatest = try { healthWriter.readLatestWeight() } catch (_: Exception) { null }
            // LWW comparison below; HealthStore filters self-written loop records.
            // Both empty
            if (miLatest == null && hcLatest == null) return@runMetric 0

            // Only one side has data
            if (miLatest == null && hcLatest != null) {
                // HC newer -> Mi
                val ok = api.uploadWeight(hcLatest)
                return@runMetric if (ok) 1 else throw IllegalStateException("Mi weight upload failed")
            }
            if (miLatest != null && hcLatest == null) {
                healthWriter.writeWeight(listOf(miLatest))
                return@runMetric 1
            }

            // Both present — LWW
            val mi = miLatest!!
            val hc = hcLatest!!
            val deltaSec = hc.timestamp - mi.timestamp
            val weightDiff = kotlin.math.abs(hc.weightKg - mi.weightKg)
            // Same instant and effectively same weight -> already synced
            if (kotlin.math.abs(deltaSec) < 60 && weightDiff < 0.05) return@runMetric 0
            if (deltaSec > 60) {
                // HC newer -> Mi (preserve timestamp)
                val ok = api.uploadWeight(hc)
                if (!ok) throw IllegalStateException("Mi weight upload failed")
                1
            } else if (deltaSec < -60) {
                // Mi newer -> HC
                healthWriter.writeWeight(listOf(mi))
                1
            } else {
                // Within 60s threshold but different weight: treat larger timestamp as winner
                if (hc.timestamp > mi.timestamp) {
                    val ok = api.uploadWeight(hc)
                    if (!ok) throw IllegalStateException("Mi weight upload failed")
                    1
                } else if (mi.timestamp > hc.timestamp) {
                    healthWriter.writeWeight(listOf(mi))
                    1
                } else {
                    0
                }
            }
        }
    }

    /** Legacy window-based weight (kept for tests); now delegates to bidirectional. */
    suspend fun syncWeight(from: String, to: String) { syncWeightBidirectional() }

    private suspend fun getMiLatestWeight(): WeightMeasurement? {
        // Primary: getLatest (server-side latest regardless of time)
        val latestViaLatest = try {
            val res = fetchSemaphore.withPermit { api.getLatest("weight", limit = 5) }
            val list = MiFitnessParsers.parseWeightMeasurements(res.result?.dataList.orEmpty().map { it.toRaw() })
            HealthDataNormalizer.normalizeWeight(list).maxByOrNull { it.timestamp }
        } catch (_: Exception) { null }
        if (latestViaLatest != null) return latestViaLatest
        // Fallback: broad by-time window (covers legacy / CN quirks)
        return try {
            val nowSec = HealthTimePolicy.nowEpochSeconds()
            val from = "1970-01-01T00:00:00Z"
            val to = Clock.System.now().toString()
            val list = MiFitnessParsers.parseWeightMeasurements(
                fetchSemaphore.withPermit { fetchAllByTime("weight", from, to) }.map { it.toRaw() },
            )
            HealthDataNormalizer.normalizeWeight(list).maxByOrNull { it.timestamp }
        } catch (_: Exception) { null }
    }

    suspend fun syncWorkouts(from: String, to: String) {
        runMetric("workouts") {
            val parsed = MiFitnessParsers.parseWorkouts(
                api.getSportRecordsByTime(from, to),
            )
            // HR samples in range — attach as series when FDS record is sparse
            val hrRaw = try {
                fetchAllByTime("heart_rate", from, to).map { it.toRaw() }
            } catch (_: Exception) {
                emptyList()
            }
            val hrSamples = MiFitnessParsers.parseHeartRateSamples(hrRaw)
            val sessions = enrichWorkouts(parsed, hrSamples)
            if (sessions.isNotEmpty()) healthWriter.writeWorkouts(sessions)
            sessions.size
        }
    }

    private suspend fun syncWorkouts(
        from: String,
        to: String,
        hrRows: kotlinx.coroutines.Deferred<List<HeartRateEntry>>,
    ) {
        runMetric("workouts") {
            val parsed = MiFitnessParsers.parseWorkouts(
                fetchSemaphore.withPermit { api.getSportRecordsByTime(from, to) },
            )
            // Shared HR rows — attach as series when FDS record is sparse.
            val hrSamples = MiFitnessParsers.parseHeartRateSamples(
                hrRows.await().map { it.toRaw() },
            )
            val sessions = enrichWorkouts(parsed, hrSamples)
            if (sessions.isNotEmpty()) healthWriter.writeWorkouts(sessions)
            sessions.size
        }
    }

    /**
     * FDS GPS/record/recover + cloud HR overlap. Failures leave partial detail so summary still syncs.
     * One shared FDS client per sync (engine/TLS setup once, not per workout).
     */
    private suspend fun enrichWorkouts(
        sessions: List<WorkoutSession>,
        hrSamples: List<com.bettermifitness.sync.data.api.HeartRateSample>,
    ): List<WorkoutSession> {
        if (sessions.isEmpty()) return sessions
        val fds = com.mifitness.miclient.fds.FdsClient(api.dataClient())
        try {
            return sessions.map { session ->
                enrichOneWorkout(session, hrSamples, fds)
            }
        } finally {
            fds.close()
        }
    }

    private suspend fun enrichOneWorkout(
        session: WorkoutSession,
        hrSamples: List<com.bettermifitness.sync.data.api.HeartRateSample>,
        fds: com.mifitness.miclient.fds.FdsClient,
    ): WorkoutSession {
        var out = session
        // Cloud HR overlapping the workout window
        val fromCloud = MiFitnessParsers.heartRateInWindow(
            hrSamples,
            session.startTime,
            session.endTime,
        )
        if (fromCloud.size > out.heartRateSeries.size) {
            out = out.copy(heartRateSeries = fromCloud)
        }
        // FDS GPS + record + recover
        if (!session.gpsDeviceSid.isNullOrBlank()) {
            out = try {
                api.enrichWorkoutDetails(out, fds, closeFds = false)
            } catch (_: Exception) {
                out
            }
        }
        // Prefer denser HR after FDS
        if (fromCloud.size > out.heartRateSeries.size) {
            out = out.copy(heartRateSeries = fromCloud)
        }
        return out
    }

    suspend fun syncBloodPressure(from: String, to: String) {
        runMetric("bloodPressure") {
            val samples = MiFitnessParsers.parseBloodPressureSamples(
                fetchSemaphore.withPermit { fetchAllByTime("blood_pressure", from, to) }
                    .map { it.toRaw() },
            )
            if (samples.isNotEmpty()) healthWriter.writeBloodPressure(samples)
            samples.size
        }
    }

    suspend fun syncTemperature(from: String, to: String) {
        runMetric("temperature") {
            // Prefer by-time series; also merge manual single_temperature latest if present.
            val byTime = fetchSemaphore.withPermit {
                fetchAllByTime("temperature_characteristic", from, to)
            }.map { it.toRaw() }
            val manual = try {
                fetchSemaphore.withPermit {
                    api.getLatest("single_temperature", limit = 30)
                }.result?.dataList.orEmpty().map { it.toRaw() }
            } catch (_: Exception) {
                emptyList()
            }
            val samples = MiFitnessParsers.parseTemperatureSamples(byTime + manual)
            if (samples.isNotEmpty()) healthWriter.writeTemperature(samples)
            samples.size
        }
    }

    suspend fun syncVo2Max(from: String, to: String) {
        runMetric("vo2Max") {
            val byTime = fetchSemaphore.withPermit {
                fetchAllByTime("vo2_max", from, to)
            }.map { it.toRaw() }
            val latest = try {
                fetchSemaphore.withPermit {
                    api.getLatest("vo2_max", limit = 30)
                }.result?.dataList.orEmpty().map { it.toRaw() }
            } catch (_: Exception) {
                emptyList()
            }
            val samples = MiFitnessParsers.parseVo2MaxSamples(byTime + latest)
            if (samples.isNotEmpty()) healthWriter.writeVo2Max(samples)
            samples.size
        }
    }

    override fun resetProgress() {
        _syncProgress.value = SyncProgress()
    }

    private suspend fun fetchAllByTime(
        key: String,
        from: String,
        to: String,
        maxPages: Int = 60,
    ): List<HeartRateEntry> {
        val all = mutableListOf<HeartRateEntry>()
        var next: String? = null
        var pages = 0
        while (pages < maxPages) {
            val res = api.getDataByTime(key, from, to, next).result ?: break
            all += res.dataList
            pages++
            if (!res.hasMore || res.nextKey.isNullOrEmpty()) break
            next = res.nextKey
        }
        return all
    }

    private suspend fun runMetric(metric: String, block: suspend () -> Int) {
        setState(metric, SyncState.InProgress)
        try {
            setState(metric, SyncState.Success(executeWithAuthRetry(block)))
        } catch (e: Exception) {
            recordFailure(e)
            setState(metric, SyncState.Error(friendlyMessage(e)))
        }
    }

    private suspend fun executeWithAuthRetry(block: suspend () -> Int): Int {
        return try {
            block()
        } catch (e: MiApiException.AuthExpired) {
            var shouldRefresh = false
            stateMutex.withLock {
                sawAuthFailure = true
                if (!authRefreshTried) {
                    authRefreshTried = true
                    shouldRefresh = true
                }
            }
            if (shouldRefresh) {
                when (val refresh = session.refreshSessionDetailed()) {
                    SessionRefreshResult.Success -> {
                        stateMutex.withLock {
                            lastRefreshUserMessage = null
                            lastRefreshRetryable = false
                        }
                        return block()
                    }
                    is SessionRefreshResult.TransientFailure -> {
                        stateMutex.withLock {
                            lastRefreshUserMessage = refresh.userMessage
                            lastRefreshRetryable = true
                        }
                    }
                    is SessionRefreshResult.NeedsReLogin,
                    is SessionRefreshResult.NeedsVerification,
                    -> {
                        stateMutex.withLock {
                            lastRefreshUserMessage = refresh.userMessage
                            lastRefreshRetryable = false
                        }
                    }
                }
            }
            throw e
        }
    }

    private suspend fun recordFailure(e: Exception) {
        stateMutex.withLock {
            when (e) {
                is MiApiException.AuthExpired -> {
                    sawAuthFailure = true
                    retryableFailures += lastRefreshRetryable
                }
                is MiApiException -> retryableFailures += e.isRetryable
                else -> retryableFailures += true
            }
        }
    }

    private fun friendlyMessage(e: Exception): String {
        return when (e) {
            is MiApiException.AuthExpired ->
                lastRefreshUserMessage
                    ?: e.message?.takeIf { it.isNotBlank() }
                    ?: "Session expired — sign in again"
            is MiApiException.Network ->
                e.message?.takeIf { it.isNotBlank() } ?: "Network error"
            is MiApiException.RateLimited ->
                "Mi cloud rate limited — try again later"
            is MiApiException.Server ->
                e.message?.takeIf { it.isNotBlank() } ?: "Mi cloud error (${e.httpOrBusinessCode})"
            is MiApiException.Unexpected ->
                e.message?.takeIf { it.isNotBlank() } ?: "Unexpected Mi API error"
            else -> e.message ?: e::class.simpleName ?: "Unknown error"
        }
    }

    private suspend fun setState(metric: String, state: SyncState) {
        stateMutex.withLock {
            _syncProgress.value = when (metric) {
                "heartRate" -> _syncProgress.value.copy(heartRate = state)
                "restingHeartRate" -> _syncProgress.value.copy(restingHeartRate = state)
                "sleep" -> _syncProgress.value.copy(sleep = state)
                "hrv" -> _syncProgress.value.copy(hrv = state)
                "steps" -> _syncProgress.value.copy(steps = state)
                "distance" -> _syncProgress.value.copy(distance = state)
                "activeCalories" -> _syncProgress.value.copy(activeCalories = state)
                "spo2" -> _syncProgress.value.copy(spo2 = state)
                "weight" -> _syncProgress.value.copy(weight = state)
                "workouts" -> _syncProgress.value.copy(workouts = state)
                "bloodPressure" -> _syncProgress.value.copy(bloodPressure = state)
                "temperature" -> _syncProgress.value.copy(temperature = state)
                "vo2Max" -> _syncProgress.value.copy(vo2Max = state)
                else -> _syncProgress.value
            }
        }
    }

    companion object {
        /** Max concurrent Mi cloud requests during parallel sync (rate-limit safety). */
        const val MAX_CONCURRENT_FETCHES = 3
    }
}
