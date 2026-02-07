package com.flatdrop.ui.components

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.coreTween
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.unit.dp
import com.flatdrop.ui.theme.liquidGlass
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.hazeChild

@RequiresApi(Build.VERSION_CODES.TIRAMISU) 
@Composable
fun LiquidDropZone(
    hazeState: HazeState,
    modifier: Modifier = Modifier,
    onFileDrop: () -> Unit = {}
) {
    val haptic = LocalHapticFeedback.current
    
    // State for hover/drag intensity
    var isHovered by remember { mutableStateOf(false) }
    
    // Animate intensity for smooth transition
    val intensity by animateFloatAsState(
        targetValue = if (isHovered) 1.0f else 0.0f,
        animationSpec = coreTween(durationMillis = 600), // Slow, liquid-like response
        label = "LiquidIntensity"
    )

    Box(
        modifier = modifier
            .size(300.dp)
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent()
                        // Simple hover detection placeholder
                        val changes = event.changes
                        if (changes.isNotEmpty()) {
                             // For simplicity, toggle on press/drag in this demo is handled below
                        }
                    }
                }
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onPress = {
                        isHovered = true
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        tryAwaitRelease()
                        isHovered = false
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    },
                    onTap = { onFileDrop() }
                )
            }
            // Apply Liquid Glass Shader & Scale Effect
            .liquidGlass(intensity)
            // Clip to shape
            .clip(RoundedCornerShape(32.dp))
            // Apply Haze (Backdrop Blur)
            .hazeChild(
                state = hazeState,
                shape = RoundedCornerShape(32.dp),
                style = dev.chrisbanes.haze.HazeStyle(
                    backgroundColor = Color.White.copy(alpha = 0.05f),
                    blurRadius = 20.dp + (10.dp * intensity) // Increase blur on hover
                )
            )
            // Silk Border
            .border(
                width = 1.dp,
                color = Color.White.copy(alpha = 0.2f),
                shape = RoundedCornerShape(32.dp)
            ),
        contentAlignment = androidx.compose.ui.Alignment.Center
    ) {
        // Inner content
        androidx.compose.material3.Text(
            text = "Drop Files Here",
            color = Color.Black.copy(alpha = 0.5f),
            style = androidx.compose.material3.MaterialTheme.typography.titleMedium
        )
    }
}
