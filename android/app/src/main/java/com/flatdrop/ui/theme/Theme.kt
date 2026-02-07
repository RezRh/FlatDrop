package com.flatdrop.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val DarkColorScheme = darkColorScheme(
    primary = ObsidianAccent,
    secondary = ObsidianTextSecondary,
    tertiary = ObsidianAccent,
    background = ObsidianBackground,
    surface = ObsidianSurface,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onTertiary = Color.White,
    onBackground = ObsidianTextPrimary,
    onSurface = ObsidianTextPrimary,
)

private val LightColorScheme = lightColorScheme(
    primary = IceAccent,
    secondary = IceTextSecondary,
    tertiary = IceAccent,
    background = IceBackground,
    surface = IceSurface,
    onPrimary = Color.White,
    onSecondary = IceTextPrimary,
    onTertiary = IceTextPrimary,
    onBackground = IceTextPrimary,
    onSurface = IceTextPrimary,
)

@Composable
fun FlatDropTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+ but we disable it to enforce Liquid Glass aesthetic
    dynamicColor: Boolean = false, 
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }
    
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            // Edge-to-edge transparency
            window.statusBarColor = Color.Transparent.toArgb()
            window.navigationBarColor = Color.Transparent.toArgb()
            
            // Icon colors
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography, // We'll assume default for now or create generic one if needed
        content = content
    )
}
