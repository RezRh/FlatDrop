package com.flatdrop.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.flatdrop.ui.theme.GlassBorderDark
import com.flatdrop.ui.theme.GlassBorderLight

@Composable
fun LiquidGlassBox(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 24.dp,
    content: @Composable BoxScope.() -> Unit
) {
    val isDark = MaterialTheme.colorScheme.background.value.red < 0.5f
    
    val glassBrush = if (isDark) {
        Brush.verticalGradient(
            colors = listOf(
                Color(0xFF2A2A2A).copy(alpha = 0.6f),
                Color(0xFF121212).copy(alpha = 0.6f)
            )
        )
    } else {
        Brush.verticalGradient(
            colors = listOf(
                Color(0xFFFFFFFF).copy(alpha = 0.7f),
                Color(0xFFF0F2F5).copy(alpha = 0.4f)
            )
        )
    }
    
    val borderColor = if (isDark) GlassBorderDark else GlassBorderLight

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(cornerRadius))
            .background(glassBrush)
            .border(
                width = 1.dp,
                color = borderColor,
                shape = RoundedCornerShape(cornerRadius)
            ),
        content = content
    )
}
