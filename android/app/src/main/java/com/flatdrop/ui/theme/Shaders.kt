package com.flatdrop.ui.theme

import org.intellij.lang.annotations.Language

object Shaders {
    @Language("AGSL")
    const val DROP_ZONE_GLSL = """
        uniform shader composable;
        uniform float2 resolution;
        uniform float intensity; // 0.0 to 1.0, driven by hover/drag

        half4 main(float2 fragCoord) {
            float2 uv = fragCoord / resolution;
            float2 center = float2(0.5, 0.5);

            // Refraction: 1.2x Magnification at max intensity
            // 1.2x zoom = 1/1.2 scale = ~0.833
            float maxScale = 0.8333;
            float scale = mix(1.0, maxScale, intensity);
            
            // Distort UVs towards center to simulate magnification
            float2 refractedUV = (uv - center) * scale + center;

            // Chromatic Aberration: varying displacement for R, G, B
            // Stronger at edges
            float dist = length(uv - center);
            float aberrationStrength = 0.02 * intensity * dist;

            // Sample the input 'composable' (which should be the blurred background from Haze)
            half4 colorG = composable.eval(refractedUV * resolution);
            half4 colorR = composable.eval((refractedUV + float2(aberrationStrength, 0.0)) * resolution);
            half4 colorB = composable.eval((refractedUV - float2(aberrationStrength, 0.0)) * resolution);

            // Combine
            return half4(colorR.r, colorG.g, colorB.b, 1.0);
        }
    """

    @Language("AGSL")
    const val MAGNETIC_INDICATOR_GLSL = """
        uniform float2 resolution;
        uniform float time;
        uniform half4 color;
        
        half4 main(float2 fragCoord) {
            float2 uv = fragCoord / resolution;
            
            // Specular Highlight
            // A sharp, diagonal white reflection moving across the surface
            // The shine moves faster than the pill itself to simulate light physics
            float shineSpeed = 1.5;
            float shineProgress = fract(time * shineSpeed);
            
            // Diagonal band math
            // x - y + offset
            float band = uv.x - uv.y * 3.0; // Steep angle
            float shineCenter = (shineProgress * 3.0) - 1.5;
            
            float dist = abs(band - shineCenter);
            float shine = smoothstep(0.1, 0.0, dist) * 0.4; // 0.4 intensity
            
            return color + half4(shine);
        }
    """
}
