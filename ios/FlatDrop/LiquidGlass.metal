#include <metal_stdlib>
#include <SwiftUI/SwiftUI_Metal.h>
using namespace metal;

/// Refractive Glass Shader
/// Implements 1.2x refraction with radial falloff and chromatic aberration
[[ stitchable ]] float2 refractiveGlass(
    float2 position,
    float2 size,
    float2 touchPosition,
    float intensity,
    float time
) {
    // Center of the view
    float2 center = size / 2.0;
    
    // Normalized coordinates (-0.5 to 0.5)
    float2 uv = (position - center) / size;
    
    // Calculate distance from touch/hover point
    // We want the distortion to be strongest at the touch point if interactive,
    // or jus center if static. Let's make it interactive.
    // If touchPosition is (-1,-1), use center.
    float2 interactionCenter = (touchPosition.x < 0) ? center : touchPosition;
    float dist = distance(position, interactionCenter);
    
    // Radial falloff for the effect
    float maxDist = length(size) * 0.5;
    float falloff = smoothstep(maxDist, 0.0, dist);
    
    // Refraction Strength (Magnification)
    // 1.2x Magnification = 1/1.2 scale = ~0.833
    // We interpolate between 1.0 (no zoom) and 0.833 (max zoom) based on intensity * falloff
    float maxZoomScale = 0.8333;
    float currentScale = mix(1.0, maxZoomScale, intensity * falloff);
    
    // Apply scale relative to center
    // New UV = (UV) * scale
    // New Position = New UV * size + center
    
    float2 newPos = (uv * currentScale) * size + center;
    
    // Add Chromatic Aberration via distortion offset
    // We return the coordinate to sample.
    // For CA, we need to sample 3 times in the color function.
    // But distortionEffect only returns ONE float2 coordinate.
    // So this shader only handles the geometric distortion (Refraction).
    // The CA must be handled in a `colorEffect` or `layerEffect` or by applying this distortion differently per channel.
    // Alternatively, we can simulate CA here by adding a slight offset based on distance, 
    // but ultimately the `distortionEffect` samples the *entire* pixel at that coord.
    // To do real CA, we need `layerEffect` which returns a half4 color.
    
    return newPos;
}

/// Chromatic Aberration & Refraction Layer Effect
/// Handles both the geometric displacement and the color splitting
[[ stitchable ]] half4 liquidGlassLayer(
    float2 position,
    SwiftUI::Layer layer,
    float2 size,
    float2 touchPosition,
    float intensity
) {
    // 1. Calculate Distortion (Same logic as above)
    float2 center = size / 2.0;
    float2 uv = (position - center) / size;
    
    float2 interactionCenter = (touchPosition.x < 0) ? center : touchPosition;
    float dist = distance(position, interactionCenter);
    float maxDist = min(size.x, size.y) * 0.5;
    
    // Falloff for the lens effect
    float falloff = smoothstep(maxDist * 1.5, 0.0, dist);
    
    // Base Refraction (Magnification)
    float scale = mix(1.0, 0.833, intensity * falloff);
    float2 warpedPos = (uv * scale) * size + center;
    
    // 2. Chromatic Aberration Offsets
    // Offset Red and Blue channels radially away from the warped position
    // Strength increases with intensity and distance from center
    float caStrength = 5.0 * intensity * falloff; // 5 pixels max spread
    
    float2 dir = normalize(position - interactionCenter);
    if (length(position - interactionCenter) < 0.001) dir = float2(0,0);
    
    float2 redPos = warpedPos + dir * caStrength;
    float2 bluePos = warpedPos - dir * caStrength;
    
    // Sample the layer
    // Note: layer.sample() expects absolute coordinates in the layer's coordinate space.
    half4 colorGreen = layer.sample(warpedPos);
    half4 colorRed = layer.sample(redPos);
    half4 colorBlue = layer.sample(bluePos);
    
    // Reconstruct pixel
    return half4(colorRed.r, colorGreen.g, colorBlue.b, colorGreen.a); // Use Green alpha or max alpha
}
