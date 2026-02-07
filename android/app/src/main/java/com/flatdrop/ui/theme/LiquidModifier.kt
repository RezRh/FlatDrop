package com.flatdrop.ui.theme

import android.graphics.RenderEffect
import android.graphics.RuntimeShader
import android.os.Build
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.graphicsLayer

fun Modifier.liquidGlass(
    intensity: Float
): Modifier = composed {
    val shader = remember {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            RuntimeShader(Shaders.DROP_ZONE_GLSL)
        } else {
            null
        }
    }

    Modifier.graphicsLayer {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && shader != null) {
            // Update AGSL Uniforms
            shader.setFloatUniform("resolution", size.width, size.height)
            shader.setFloatUniform("intensity", intensity)
            
            // Apply Shader as RenderEffect
            // We recreate the RenderEffect to ensure the uniform updates are picked up by the drawing layer
            renderEffect = RenderEffect
                .createRuntimeShaderEffect(shader, "composable")
                .asComposeRenderEffect()
        }
        
        // Physical warping (Scale) - subtle pop
        val scale = 1.0f + (intensity * 0.02f)
        scaleX = scale
        scaleY = scale
    }
}
