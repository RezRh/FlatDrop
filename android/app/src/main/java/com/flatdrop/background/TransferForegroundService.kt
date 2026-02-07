package com.flatdrop.background

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.flatdrop.MainActivity
import com.flatdrop.R
import com.flatdrop.core.FlatDropCore
import flatdrop.messages.Flatdrop.*
import kotlinx.coroutines.*

/**
 * AirDrop-Class Background Transfer for Android
 * 
 * Uses ForegroundService with dataSync type (Android 14+)
 * Guarantees uninterrupted transfers even when app is backgrounded
 */
class TransferForegroundService : Service() {
    
    companion object {
        const val CHANNEL_ID = "flatdrop_transfer_channel"
        const val NOTIFICATION_ID = 1001
        
        const val ACTION_START_TRANSFER = "com.flatdrop.action.START_TRANSFER"
        const val ACTION_STOP_TRANSFER = "com.flatdrop.action.STOP_TRANSFER"
        const val ACTION_UPDATE_PROGRESS = "com.flatdrop.action.UPDATE_PROGRESS"
        const val ACTION_PAUSE_TRANSFER = "com.flatdrop.action.PAUSE_TRANSFER"
        const val ACTION_RESUME_TRANSFER = "com.flatdrop.action.RESUME_TRANSFER"
        const val ACTION_TRANSFER_STATE = "com.flatdrop.action.TRANSFER_STATE"
        
        const val EXTRA_TRANSFER_ID = "transfer_id"
        const val EXTRA_FILE_NAME = "file_name"
        const val EXTRA_PROGRESS = "progress"
        const val EXTRA_DESCRIPTION = "description"
        const val EXTRA_TRANSFER_STATE = "transfer_state"
        
        // Tracks active transfers to prevent service stop during multi-file transfers
        private val activeTransfers = mutableSetOf<String>()
        private val transferNames = mutableMapOf<String, String>()
        private var serviceJob: Job? = null
        
        fun startTransfer(context: Context, transferId: String, fileName: String, description: String) {
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_START_TRANSFER
                putExtra(EXTRA_TRANSFER_ID, transferId)
                putExtra(EXTRA_FILE_NAME, fileName)
                putExtra(EXTRA_DESCRIPTION, description)
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
        
        fun updateProgress(context: Context, transferId: String, progress: Double, description: String) {
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_UPDATE_PROGRESS
                putExtra(EXTRA_TRANSFER_ID, transferId)
                putExtra(EXTRA_PROGRESS, progress)
                putExtra(EXTRA_DESCRIPTION, description)
            }
            context.startService(intent)
        }
        
        fun stopTransfer(context: Context, transferId: String) {
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_STOP_TRANSFER
                putExtra(EXTRA_TRANSFER_ID, transferId)
            }
            context.startService(intent)
        }

        fun pauseTransfer(context: Context, transferId: String) {
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_PAUSE_TRANSFER
                putExtra(EXTRA_TRANSFER_ID, transferId)
            }
            context.startService(intent)
        }

        fun resumeTransfer(context: Context, transferId: String) {
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_RESUME_TRANSFER
                putExtra(EXTRA_TRANSFER_ID, transferId)
            }
            context.startService(intent)
        }
    }
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_TRANSFER -> {
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID) ?: return START_STICKY
                val fileName = intent.getStringExtra(EXTRA_FILE_NAME) ?: "File"
                val description = intent.getStringExtra(EXTRA_DESCRIPTION) ?: "Transferring..."
                
                activeTransfers.add(transferId)
                transferNames[transferId] = fileName
                startForeground(transferId, fileName, description, 0.0)
                startRustEventPoller()
            }
            
            ACTION_UPDATE_PROGRESS -> {
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID) ?: return START_STICKY
                val progress = intent.getDoubleExtra(EXTRA_PROGRESS, 0.0)
                val description = intent.getStringExtra(EXTRA_DESCRIPTION) ?: "Transferring..."
                
                updateNotification(transferId, description, progress)
            }
            
            ACTION_STOP_TRANSFER -> {
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID) ?: return START_STICKY
                activeTransfers.remove(transferId)
                transferNames.remove(transferId)
                
                // Only stop service when all transfers complete
                if (activeTransfers.isEmpty()) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            ACTION_PAUSE_TRANSFER -> {
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID) ?: return START_STICKY
                val command = UiCommand.newBuilder()
                    .setPauseTransfer(
                        PauseTransferRequest.newBuilder()
                            .setTransferId(transferId)
                            .build()
                    )
                    .build()
                FlatDropCore.hubSendCommand(command.toByteArray())
            }
            ACTION_RESUME_TRANSFER -> {
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID) ?: return START_STICKY
                val command = UiCommand.newBuilder()
                    .setResumeTransfer(
                        ResumeTransferRequest.newBuilder()
                            .setTransferId(transferId)
                            .build()
                    )
                    .build()
                FlatDropCore.hubSendCommand(command.toByteArray())
            }
        }
        
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    private fun startForeground(transferId: String, fileName: String, description: String, progress: Double) {
        val notification = createNotification(transferId, fileName, description, progress, false)
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+ - Use dataSync foreground service type
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Android 10-13
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            // Android 9 and below
            startForeground(NOTIFICATION_ID, notification)
        }
    }
    
    private fun createNotification(
        transferId: String,
        fileName: String,
        description: String,
        progress: Double,
        isPaused: Boolean
    ): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val progressInt = (progress * 100).toInt()
        val progressText = if (isPaused) {
            "Paused $progressInt%"
        } else if (progress > 0) {
            "$progressInt%"
        } else {
            "Starting..."
        }
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("FlatDrop Transfer")
            .setContentText("$progressText - $fileName")
            .setSmallIcon(R.drawable.ic_transfer_notification)
            .setOngoing(!isPaused)
            .setOnlyAlertOnce(true)
            .setProgress(100, progressInt, progress == 0.0 && !isPaused)
            .setContentIntent(pendingIntent)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .apply {
                if (isPaused) {
                    addAction(
                        R.drawable.ic_play,
                        "Resume",
                        createResumePendingIntent(transferId)
                    )
                } else {
                    addAction(
                        R.drawable.ic_pause,
                        "Pause",
                        createPausePendingIntent(transferId)
                    )
                }
                addAction(
                    R.drawable.ic_cancel,
                    "Cancel",
                    createCancelPendingIntent()
                )
            }
            .build()
    }
    
    private fun updateNotification(transferId: String, description: String, progress: Double, isPaused: Boolean = false) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        val fileName = transferNames[transferId] ?: "Transfer"
        
        val notification = createNotification(transferId, fileName, description, progress, isPaused)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "File Transfers",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress of ongoing file transfers"
                setShowBadge(false)
                enableVibration(false)
            }
            
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createCancelPendingIntent(): PendingIntent {
        val intent = Intent(this, TransferForegroundService::class.java).apply {
            action = ACTION_STOP_TRANSFER
        }
        return PendingIntent.getService(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun createPausePendingIntent(transferId: String): PendingIntent {
        val intent = Intent(this, TransferForegroundService::class.java).apply {
            action = ACTION_PAUSE_TRANSFER
            putExtra(EXTRA_TRANSFER_ID, transferId)
        }
        return PendingIntent.getService(
            this,
            ("pause_$transferId").hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun createResumePendingIntent(transferId: String): PendingIntent {
        val intent = Intent(this, TransferForegroundService::class.java).apply {
            action = ACTION_RESUME_TRANSFER
            putExtra(EXTRA_TRANSFER_ID, transferId)
        }
        return PendingIntent.getService(
            this,
            ("resume_$transferId").hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun broadcastTransferState(state: TransferStateChanged) {
        val intent = Intent(ACTION_TRANSFER_STATE).apply {
            putExtra(EXTRA_TRANSFER_STATE, state.toByteArray())
        }
        sendBroadcast(intent)
    }
    
    /**
     * Polls Rust for TransferStateChanged events
     * Updates notification based on transfer state
     */
    private fun startRustEventPoller() {
        serviceJob?.cancel()
        serviceJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive && activeTransfers.isNotEmpty()) {
                try {
                    // Poll for events from Rust
                    val eventBytes = FlatDropCore.hubPollEvent()
                    
                    if (eventBytes.isNotEmpty()) {
                        val rustEvent = RustEvent.parseFrom(eventBytes)
                        
                        if (rustEvent.eventCase == RustEvent.EventCase.TRANSFER_STATE_CHANGED) {
                            val state = rustEvent.transferStateChanged

                            when (state.state) {
                                TransferStateChanged.State.PREPARING -> {
                                    updateNotification(
                                        state.transferId,
                                        state.description,
                                        0.0
                                    )
                                    broadcastTransferState(state)
                                }
                                
                                TransferStateChanged.State.IN_PROGRESS -> {
                                    updateNotification(
                                        state.transferId,
                                        state.description,
                                        state.progress
                                    )
                                    broadcastTransferState(state)
                                }
                                
                                TransferStateChanged.State.PAUSED -> {
                                    updateNotification(
                                        state.transferId,
                                        state.description,
                                        state.progress,
                                        true
                                    )
                                    broadcastTransferState(state)
                                }

                                TransferStateChanged.State.FINISHED,
                                TransferStateChanged.State.FAILED,
                                TransferStateChanged.State.CANCELLED -> {
                                    // Mark transfer as complete
                                    activeTransfers.remove(state.transferId)
                                    
                                    if (activeTransfers.isEmpty()) {
                                        withContext(Dispatchers.Main) {
                                            stopForeground(STOP_FOREGROUND_REMOVE)
                                            stopSelf()
                                        }
                                    }
                                    broadcastTransferState(state)
                                }
                                
                                else -> { /* Ignore other states */ }
                            }
                        }
                    }
                    
                    delay(100) // Poll every 100ms
                } catch (e: Exception) {
                    e.printStackTrace()
                    delay(500) // Back off on error
                }
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        serviceJob?.cancel()
        activeTransfers.clear()
    }
}
