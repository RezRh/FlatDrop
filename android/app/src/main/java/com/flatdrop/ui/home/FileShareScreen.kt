package com.flatdrop.ui.home

import android.os.Build
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.flatdrop.ui.components.LiquidDropZone
import com.flatdrop.ui.components.MagneticNavigation
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.haze

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
fun FileShareScreen() {
    val context = LocalContext.current
    // Hoist Haze State
    val hazeState = remember { HazeState() }
    
    // Navigation State
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Nearby", "Recent", "Cloud")

    // Dynamic background brush for refraction testing
    val backgroundBrush = remember {
        androidx.compose.ui.graphics.Brush.verticalGradient(
            colors = listOf(
                Color(0xFFE0E0E0),
                Color(0xFFF5F5F5),
                Color(0xFFE0E0E0)
            )
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(backgroundBrush)
            .haze(
                state = hazeState,
                backgroundColor = Color(0xFFF5F5F5),
                noiseFactor = 0.0f
            )
    ) {
        // Decorative blobs for refraction
        Canvas(modifier = Modifier.fillMaxSize()) {
            drawCircle(
                color = Color(0xFFFF6F61).copy(alpha = 0.15f),
                radius = 300f,
                center = center.copy(y = center.y - 200f)
            )
            drawCircle(
                color = Color(0xFF6B5B95).copy(alpha = 0.15f),
                radius = 400f,
                center = center.copy(x = center.x + 200f, y = center.y + 200f)
            )
            drawCircle(
                color = Color(0xFF88B04B).copy(alpha = 0.15f),
                radius = 250f,
                center = center.copy(x = center.x - 200f, y = center.y + 400f)
            )
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.systemBars) // Handle system bars automatically
                .padding(24.dp)
                .widthIn(max = 600.dp)
                .align(Alignment.Center),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Header
            Text(
                text = "FlatDrop",
                style = androidx.compose.material3.MaterialTheme.typography.displayMedium,
                color = Color.Black.copy(alpha = 0.8f)
            )
            
            Spacer(modifier = Modifier.weight(1f))
            
            // Liquid Drop Zone
            Box(
                contentAlignment = Alignment.Center
            ) {
                LiquidDropZone(
                     hazeState = hazeState,
                     onFileDrop = { 
                         Toast.makeText(context, "Scanning for devices...", Toast.LENGTH_SHORT).show()
                     }
                )
            }
            
            Spacer(modifier = Modifier.weight(1f))
            
            // Magnetic Navigation
            MagneticNavigation(
                items = tabs,
                selectedIndex = selectedTab,
                onItemSelected = { 
                    selectedTab = it
                    // Haptic feedback could be added here
                   Toast.makeText(context, "Switched to ${tabs[it]}", Toast.LENGTH_SHORT).show()
                }
            )
            
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}
