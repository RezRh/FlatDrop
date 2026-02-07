import SwiftUI

// MARK: - Liquid Glass Modifier

extension View {
    func liquidGlass(intensity: CGFloat, touchPosition: CGPoint) -> some View {
        self.visualEffect { content, geometryProxy in
            content.layerEffect(
                ShaderLibrary.liquidGlassLayer(
                    .float2(geometryProxy.size),
                    .float2(touchPosition),
                    .float(intensity)
                ),
                maxSampleOffset: .zero
            )
        }
    }
}

// MARK: - Magnetic Navigation Component

struct MagneticNavigation: View {
    let items: [String]
    @Binding var selection: Int
    @Namespace private var namespace
    
    var body: some View {
        HStack(spacing: 0) {
            ForEach(items.indices, id: \.self) { index in
                Button(action: {
                    withAnimation(.spring(response: 0.5, dampingFraction: 0.75)) {
                        selection = index
                    }
                }) {
                    Text(items[index])
                        .font(.system(size: 16, weight: .medium, design: .rounded))
                        .foregroundColor(selection == index ? .black : .gray)
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                        .background {
                            if selection == index {
                                Capsule()
                                    .fill(Color.white)
                                    .matchedGeometryEffect(id: "nav", in: namespace)
                                    .shadow(color: .black.opacity(0.1), radius: 5, x: 0, y: 2)
                            }
                        }
                }
                .buttonStyle(PlainButtonStyle()) // Remove default button press effect for cleaner UI
            }
        }
        .padding(4)
        .background {
            Capsule()
                .fill(Color.black.opacity(0.05))
        }
        .frame(height: 58)
        .padding(.horizontal)
    }
}

// MARK: - File Share Screen

struct FileShareScreen: View {
    @State private var intensity: CGFloat = 0.0
    @State private var touchData: CGPoint = .zero
    @State private var selectedTab = 0
    let tabs = ["Nearby", "Recent", "Cloud"]
    
    var body: some View {
        ZStack {
            // Background Gradient
            LinearGradient(
                colors: [Color(white: 0.9), Color(white: 0.95)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
            
            // Decorative blobs for Refraction Demo
            Circle()
                .fill(Color.blue.opacity(0.2))
                .frame(width: 300, height: 300)
                .offset(x: -100, y: -200)
                .blur(radius: 50)
            
            Circle()
                .fill(Color.red.opacity(0.2))
                .frame(width: 250, height: 250)
                .offset(x: 100, y: 100)
                .blur(radius: 40)
            
            VStack {
                Spacer()
                
                // Header
                Text("FlatDrop")
                    .font(.system(size: 34, weight: .bold, design: .default))
                    .foregroundColor(.black.opacity(0.8))
                
                Spacer()
                
                // Liquid Drop Zone
                ZStack {
                    RoundedRectangle(cornerRadius: 40)
                        .fill(.ultraThinMaterial) // Glass Effect Base
                        .frame(width: 300, height: 300)
                        .liquidGlass(intensity: intensity, touchPosition: touchData) // Custom Metal Shader
                        .onContinuousHover { phase in
                            switch phase {
                            case .active(let location):
                                withAnimation(.interactiveSpring) {
                                    intensity = 1.0
                                    touchData = location
                                }
                            case .ended:
                                withAnimation(.spring(response: 0.6, dampingFraction: 0.6)) {
                                    intensity = 0.0
                                }
                            }
                        }
                        .gesture(
                            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                                .onChanged { value in
                                    withAnimation(.interactiveSpring) {
                                        intensity = 1.0
                                        touchData = value.location
                                    }
                                }
                                .onEnded { _ in
                                    withAnimation(.spring(response: 0.6, dampingFraction: 0.6)) {
                                        intensity = 0.0
                                    }
                                }
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 40)
                                .stroke(Color.white.opacity(0.2), lineWidth: 1)
                        )
                    
                    VStack(spacing: 12) {
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)
                            .scaleEffect(1.0 + (intensity * 0.1))
                            .symbolEffect(.bounce, value: intensity) // iOS 17 bounce effect
                        
                        Text("Drop Files Here")
                            .font(.headline)
                            .foregroundColor(.secondary)
                    }
                }
                
                Spacer()
                
                // Magnetic Navigation
                MagneticNavigation(
                    items: tabs,
                    selection: $selectedTab
                )
                
                Spacer().frame(height: 50)
            }
        }
    }
}

// MARK: - Preview
#Preview {
    FileShareScreen()
}
