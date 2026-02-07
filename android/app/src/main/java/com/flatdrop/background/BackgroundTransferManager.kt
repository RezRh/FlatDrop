package com.flatdrop.background

import android.content.Context
import flatdrop.messages.Flatdrop.*

/**
 * Helper class for managing background transfers
 * Call this from your UI when TransferStateChanged events are received
 */
object BackgroundTransferManager {
    
    /**
     * Handle TransferStateChanged events from Rust
     * Automatically manages ForegroundService lifecycle
     */
    fun handleTransferStateChange(context: Context, state: TransferStateChanged) {
        when (state.state) {
            TransferStateChanged.State.PREPARING,
            TransferStateChanged.State.IN_PROGRESS -> {
                // Start or update foreground service
                if (state.state == TransferStateChanged.State.PREPARING) {
                    TransferForegroundService.startTransfer(
                        context,
                        state.transferId,
                        state.fileName,
                        state.description
                    )
                } else {
                    TransferForegroundService.updateProgress(
                        context,
                        state.transferId,
                        state.progress,
                        state.description
                    )
                }
            }
            
            TransferStateChanged.State.PAUSED -> {
                TransferForegroundService.updateProgress(
                    context,
                    state.transferId,
                    state.progress,
                    state.description
                )
            }
            
            TransferStateChanged.State.FINISHED,
            TransferStateChanged.State.FAILED,
            TransferStateChanged.State.CANCELLED -> {
                // Stop foreground service
                TransferForegroundService.stopTransfer(context, state.transferId)
            }
            
            else -> { /* IDLE - no action needed */ }
        }
    }
    
    /**
     * Format bytes to human-readable string
     */
    fun formatBytes(bytes: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var size = bytes.toDouble()
        var unitIndex = 0
        
        while (size >= 1024 && unitIndex < units.size - 1) {
            size /= 1024
            unitIndex++
        }
        
        return "%.2f %s".format(size, units[unitIndex])
    }
    
    /**
     * Format transfer speed
     */
    fun formatSpeed(mbps: Double): String {
        return when {
            mbps >= 1000 -> "%.2f GB/s".format(mbps / 1000)
            mbps >= 1 -> "%.2f MB/s".format(mbps)
            else -> "%.0f KB/s".format(mbps * 1000)
        }
    }
}
