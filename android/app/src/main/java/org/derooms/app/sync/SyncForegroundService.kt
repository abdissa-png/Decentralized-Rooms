package org.derooms.app.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import org.derooms.app.MainActivity
import java.io.File

/**
 * Foreground service kept while the user expects active mesh / relay sync.
 * Does not bypass Doze forever — Android still throttles radios; this keeps
 * a visible ongoing notification so opportunistic work is less likely to be
 * killed immediately. See `docs/battery-doze.md`.
 *
 * Soak evidence: prefs + `files/sync_fgs.stamp` + periodic heartbeat log.
 */
class SyncForegroundService : Service() {
    private val heartbeat = Handler(Looper.getMainLooper())
    private val beatRunnable = object : Runnable {
        override fun run() {
            stampHeartbeat()
            heartbeat.postDelayed(this, HEARTBEAT_MS)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                heartbeat.removeCallbacks(beatRunnable)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                Log.i(TAG, "E2E_SYNC_FGS_STOP")
                return START_NOT_STICKY
            }
            else -> {
                ensureChannel()
                val notif = buildNotification()
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(
                        NOTIF_ID,
                        notif,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                    )
                } else {
                    startForeground(NOTIF_ID, notif)
                }
                val now = System.currentTimeMillis()
                getSharedPreferences(OpportunisticSyncWorker.PREFS, MODE_PRIVATE)
                    .edit()
                    .putLong(PREF_FGS_STARTED, now)
                    .putLong(PREF_FGS_HEARTBEAT, now)
                    .apply()
                writeStampFile(now, heartbeat = false)
                Log.i(TAG, "E2E_SYNC_FGS_START")
                heartbeat.removeCallbacks(beatRunnable)
                heartbeat.postDelayed(beatRunnable, HEARTBEAT_MS)
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        heartbeat.removeCallbacks(beatRunnable)
        super.onDestroy()
    }

    private fun stampHeartbeat() {
        val now = System.currentTimeMillis()
        getSharedPreferences(OpportunisticSyncWorker.PREFS, MODE_PRIVATE)
            .edit()
            .putLong(PREF_FGS_HEARTBEAT, now)
            .apply()
        writeStampFile(now, heartbeat = true)
        Log.i(TAG, "E2E_SYNC_FGS_HEARTBEAT ts=$now")
    }

    private fun writeStampFile(ts: Long, heartbeat: Boolean) {
        try {
            val f = File(filesDir, STAMP_FILE)
            f.writeText(
                buildString {
                    appendLine("ts=$ts")
                    appendLine("heartbeat=${if (heartbeat) 1 else 0}")
                },
            )
        } catch (_: Exception) {
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val ch = NotificationChannel(
            CHANNEL_ID,
            "Opportunistic sync",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Keeps Rooms ready for BLE / relay / LAN sync bursts"
        }
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, SyncForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Rooms sync active")
            .setContentText("Foreground sync — tap Sync now after Doze; Stop when idle")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stop)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val TAG = "DEROOMS_SYNC"
        const val CHANNEL_ID = "derooms_sync"
        const val NOTIF_ID = 4402
        const val ACTION_STOP = "org.derooms.app.sync.STOP"
        const val PREF_FGS_STARTED = "fgs_started_ms"
        const val PREF_FGS_HEARTBEAT = "fgs_heartbeat_ms"
        const val STAMP_FILE = "sync_fgs.stamp"
        const val HEARTBEAT_MS = 60_000L

        fun start(context: Context) {
            val i = Intent(context, SyncForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, SyncForegroundService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}
