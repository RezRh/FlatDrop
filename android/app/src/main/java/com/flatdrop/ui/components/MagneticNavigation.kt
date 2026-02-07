package com.flatdrop.ui.components

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.VectorConverter
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.unit.dp
import com.flatdrop.ui.theme.specularShine
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.roundToInt

@Composable
fun MagneticNavigation(
    items: List<String>,
    selectedIndex: Int,
    onItemSelected: (Int) -> Unit
) {
    val density = LocalDensity.current
    val haptic = LocalHapticFeedback.current
    val itemPositions = remember { mutableStateListOf<Float>() }
    val itemWidths = remember { mutableStateListOf<Float>() }
    
    // Initialize lists if empty
    if (itemPositions.isEmpty()) {
        repeat(items.size) { 
            itemPositions.add(0f)
            itemWidths.add(0f)
        }
    }

    val scope = rememberCoroutineScope()
    
    // Animatable for the indicator offset (X position)
    val indicatorOffset = remember { Animatable(0f) }
    
    // Animatable for the indicator width
    val indicatorWidth = remember { Animatable(0f) }

    // Logic to update animation target when selection changes
    LaunchedEffect(selectedIndex, itemPositions.isNotEmpty()) {
        if (itemPositions.isNotEmpty() && selectedIndex < itemPositions.size) {
            val targetX = itemPositions[selectedIndex]
            val targetW = itemWidths[selectedIndex]
            
            launch {
                indicatorOffset.animateTo(
                    targetValue = targetX,
                    animationSpec = spring(
                        dampingRatio = 0.75f,
                        stiffness = Spring.StiffnessLow
                    )
                )
            }
            launch {
                indicatorWidth.animateTo(
                    targetValue = targetW,
                    animationSpec = spring(
                        dampingRatio = 0.75f,
                        stiffness = Spring.StiffnessLow
                    )
                )
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(64.dp)
            .padding(16.dp)
            .background(Color.Black.copy(alpha = 0.05f), RoundedCornerShape(32.dp))
            .padding(4.dp)
    ) {
        // The "Liquid Flow" Indicator
        Box(
            modifier = Modifier
                .height(48.dp) // Fill height of the container minus padding
                .graphicsLayer {
                    translationX = indicatorOffset.value
                    
                    // Liquid Stretch Logic
                    // Calculate "velocity" effect based on difference between current and target? OR actual velocity.
                    // Accessing internal velocity of Animatable is possible.
                    val velocity = indicatorOffset.velocity
                    
                    // Stretch based on speed. 
                    // Max stretch 1.5x at high speed.
                    val stretchFactor = 1.0f + (abs(velocity) / 3000f).coerceAtMost(0.5f)
                    
                    scaleX = stretchFactor
                    
                    // Adjust transform origin to simulate "pulling"
                    // If moving right (velocity > 0), pivot is Left (so it stretches right).
                    // If moving left (velocity < 0), pivot is Right (so it stretches left).
                    // But we need to handle the "catch up" phase where it compresses?
                    // "Stretches toward destination" implies leading edge moves faster.
                    transformOrigin = if (velocity > 0) {
                        TransformOrigin(0f, 0.5f) // Anchor left, stretch right
                    } else {
                        TransformOrigin(1f, 0.5f) // Anchor right, stretch left
                    }
                }
                .width(
                    with(density) { indicatorWidth.value.toDp() }
                )
                .clip(RoundedCornerShape(24.dp))
                .background(Color.White) // Base white layer
                .specularShine(Color.White) // Animated specular highlight


        // The Items
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            items.forEachIndexed { index, item ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp)
                        .clickable { 
                            onItemSelected(index)
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress) // Using LongPress for a heavier "magnetic" feel or TextHandleMove
                        }
                        .onGloballyPositioned { coordinates ->
                            val pos = coordinates.positionInParent().x
                            val width = coordinates.size.width.toFloat()
                            if (index < itemPositions.size) {
                                itemPositions[index] = pos
                                itemWidths[index] = width
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = item,
                        color = if (index == selectedIndex) Color.Black else Color.Gray
                    )
                }
            }
        }
    }
}
