package org.derooms.app.sync

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Opportunistic sync hint under Doze / App Standby.
 *
 * WorkManager runs when the OS allows (battery not low + network).
 * Actual BLE / relay / LAN transfer still requires radios + peer availability;
 * this worker stamps a wake marker and writes a soak-friendly file.
 * Manual **Sync now** remains the reliable path (FR-UX-006).
 * See `docs/battery-doze.md`.
 */
class OpportunisticSyncWorker(
    context: Context,
    params: WorkerParameters,
) : Worker(context, params) {
    override fun doWork(): Result {
        val prefs = applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val prev = prefs.getLong(PREF_LAST_OPPORTUNISTIC, 0L)
        prefs.edit()
            .putLong(PREF_LAST_OPPORTUNISTIC, now)
            .putLong(PREF_LAST_GAP_MS, if (prev > 0) now - prev else 0L)
            .apply()
        try {
            val stamp = File(applicationContext.filesDir, STAMP_FILE)
            stamp.writeText("ts=$now\nprev_gap_ms=${if (prev > 0) now - prev else 0}\n")
        } catch (_: Exception) {
        }
        try {
            applicationContext.sendBroadcast(
                Intent(ACTION_OPPORTUNISTIC)
                    .setPackage(applicationContext.packageName)
                    .putExtra(EXTRA_TS, now),
            )
        } catch (_: Exception) {
        }
        Log.i(TAG, "E2E_SYNC_OPPORTUNISTIC ts=$now prev_gap_ms=${if (prev > 0) now - prev else 0}")
        return Result.success()
    }

    companion object {
        const val TAG = "DEROOMS_SYNC"
        const val PREFS = "derooms_sync"
        const val PREF_LAST_OPPORTUNISTIC = "last_opportunistic_ms"
        const val PREF_LAST_GAP_MS = "last_opportunistic_gap_ms"
        const val UNIQUE_PERIODIC = "derooms_opportunistic_sync"
        const val UNIQUE_NOW = "derooms_opportunistic_sync_now"
        const val STAMP_FILE = "sync_opportunistic.stamp"
        const val ACTION_OPPORTUNISTIC = "org.derooms.app.SYNC_OPPORTUNISTIC"
        const val EXTRA_TS = "ts"

        fun enqueuePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(true)
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val req = PeriodicWorkRequestBuilder<OpportunisticSyncWorker>(6, TimeUnit.HOURS)
                .setConstraints(constraints)
                .addTag(UNIQUE_PERIODIC)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_PERIODIC,
                ExistingPeriodicWorkPolicy.UPDATE,
                req,
            )
            Log.i(TAG, "E2E_SYNC_WM_ENQUEUED")
        }

        /** Immediate one-shot (Sync now / lab). Prefer expedited when allowed. */
        fun enqueueNow(context: Context) {
            // No network/battery constraints — Sync now must fire for soak markers
            // even when radios are off (stamp only; transfer still needs peers).
            val builder = OneTimeWorkRequestBuilder<OpportunisticSyncWorker>()
                .addTag(UNIQUE_NOW)
                .setConstraints(Constraints.Builder().build())
            try {
                builder.setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            } catch (_: Exception) {
            }
            WorkManager.getInstance(context).enqueueUniqueWork(
                UNIQUE_NOW,
                ExistingWorkPolicy.REPLACE,
                builder.build(),
            )
            try {
                val now = System.currentTimeMillis()
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putLong("last_sync_now_ms", now)
                    .apply()
                File(context.filesDir, "sync_now.stamp").writeText("ts=$now\n")
            } catch (_: Exception) {
            }
            Log.i(TAG, "E2E_SYNC_WM_NOW")
        }

        fun lastOpportunisticMs(context: Context): Long =
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getLong(PREF_LAST_OPPORTUNISTIC, 0L)
    }
}
