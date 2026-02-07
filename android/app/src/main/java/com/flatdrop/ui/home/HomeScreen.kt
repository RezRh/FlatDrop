package com.flatdrop.ui.home

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.flatdrop.background.TransferForegroundService
import com.flatdrop.ui.components.LiquidGlassBox
import flatdrop.messages.Flatdrop.TransferDirection
import flatdrop.messages.Flatdrop.TransferStateChanged

data class UiTransfer(
    val id: String,
    val fileName: String,
    val description: String,
    val progress: Double,
    val state: TransferStateChanged.State,
    val direction: TransferDirection
)

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    var transfers by remember { mutableStateOf<Map<String, UiTransfer>>(emptyMap()) }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action != TransferForegroundService.ACTION_TRANSFER_STATE) return
                val bytes = intent.getByteArrayExtra(TransferForegroundService.EXTRA_TRANSFER_STATE) ?: return
                val state = TransferStateChanged.parseFrom(bytes)

                transfers = when (state.state) {
                    TransferStateChanged.State.FINISHED,
                    TransferStateChanged.State.FAILED,
                    TransferStateChanged.State.CANCELLED -> {
                        transfers - state.transferId
                    }
                    else -> {
                        val transfer = UiTransfer(
                            id = state.transferId,
                            fileName = state.fileName,
                            description = state.description,
                            progress = state.progress,
                            state = state.state,
                            direction = state.direction
                        )
                        transfers + (state.transferId to transfer)
                    }
                }
            }
        }

        val filter = IntentFilter(TransferForegroundService.ACTION_TRANSFER_STATE)
        context.registerReceiver(receiver, filter)

        onDispose {
            context.unregisterReceiver(receiver)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "FlatDrop",
                style = MaterialTheme.typography.displayMedium.copy(
                    fontWeight = FontWeight.Bold,
                    fontSize = 32.sp,
                    color = MaterialTheme.colorScheme.onBackground
                )
            )

            Text(
                text = "Secure Local Transfer",
                style = MaterialTheme.typography.bodyLarge.copy(
                    color = MaterialTheme.colorScheme.secondary
                )
            )

            Spacer(modifier = Modifier.height(48.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                LiquidGlassBox(
                    modifier = Modifier
                        .weight(1f)
                        .height(180.dp)
                        .clickable { }
                ) {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.ArrowUpward,
                            contentDescription = "Send",
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "Send",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.SemiBold
                            )
                        )
                    }
                }

                LiquidGlassBox(
                    modifier = Modifier
                        .weight(1f)
                        .height(180.dp)
                        .clickable { }
                ) {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.ArrowUpward,
                            contentDescription = "Receive",
                            modifier = Modifier
                                .size(48.dp)
                                .rotation(180f),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "Receive",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.SemiBold
                            )
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            LiquidGlassBox(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(200.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Recent Activity",
                        style = MaterialTheme.typography.titleMedium.copy(
                            color = MaterialTheme.colorScheme.secondary
                        )
                    )

                    if (transfers.isEmpty()) {
                        Text(
                            text = "No active transfers",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    } else {
                        transfers.values.forEach { transfer ->
                            TransferItem(
                                transfer = transfer,
                                onPauseClick = {
                                    TransferForegroundService.pauseTransfer(context, transfer.id)
                                },
                                onResumeClick = {
                                    TransferForegroundService.resumeTransfer(context, transfer.id)
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

fun Modifier.rotation(degrees: Float) = this.then(
    Modifier.graphicsLayer(rotationZ = degrees)
)

@Composable
private fun TransferItem(
    transfer: UiTransfer,
    onPauseClick: () -> Unit,
    onResumeClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = transfer.fileName.ifBlank { transfer.id },
                    style = MaterialTheme.typography.bodyLarge.copy(
                        fontWeight = FontWeight.SemiBold
                    )
                )
                Text(
                    text = transfer.description,
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = MaterialTheme.colorScheme.secondary
                    )
                )
            }

            val progressPercent = (transfer.progress * 100).toInt().coerceIn(0, 100)
            Text(
                text = "$progressPercent%",
                style = MaterialTheme.typography.bodyMedium
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            val isPaused = transfer.state == TransferStateChanged.State.PAUSED
            val isInProgress = transfer.state == TransferStateChanged.State.IN_PROGRESS

            if (isPaused || isInProgress) {
                Button(
                    onClick = {
                        if (isPaused) {
                            onResumeClick()
                        } else {
                            onPauseClick()
                        }
                    }
                ) {
                    Text(if (isPaused) "Resume" else "Pause")
                }
            }
        }
    }
}
