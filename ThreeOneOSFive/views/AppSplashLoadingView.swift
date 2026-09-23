import SwiftUI

struct AppSplashLoadingView: View {
    @State private var rotation: Double = 0
    @State private var pulseScale: CGFloat = 1.0
    @State private var loadingProgress: CGFloat = 0.0
    @State private var statusIndex = 0

    private let statusMessages = [
        "Inicializando ZeroM$...",
        "Carregando módulos de segurança...",
        "Verificando integridade do sistema...",
        "Pronto!"
    ]

    var body: some View {
        ZStack {
            AnimatedHyperBackdrop()
                .ignoresSafeArea()

            Color.black.opacity(0.28)
                .ignoresSafeArea()

            VStack(spacing: 28) {
                Spacer()

                // Logo with Glow Pulse
                VStack(spacing: 12) {
                    BrandLogoView(height: 52)
                        .scaleEffect(pulseScale)
                        .shadow(color: AppTheme.accent.opacity(0.65), radius: 24, y: 0)

                    Text("ZeroM$")
                        .font(.system(size: 20, weight: .black, design: .rounded))
                        .tracking(2.5)
                        .foregroundStyle(.white)

                    Text("VERSION 1.1.0")
                        .font(.system(size: 11, weight: .heavy, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.5))
                        .tracking(1.5)
                }

                Spacer()

                // Cyber Loading Indicator
                VStack(spacing: 16) {
                    ZStack {
                        // Background ring
                        Circle()
                            .stroke(Color.white.opacity(0.08), lineWidth: 3.5)
                            .frame(width: 44, height: 44)

                        // Glowing rotating arc
                        Circle()
                            .trim(from: 0.15, to: 0.85)
                            .stroke(
                                AngularGradient(
                                    gradient: Gradient(colors: [
                                        AppTheme.accent,
                                        Color(hue: 0.78, saturation: 0.9, brightness: 1.0),
                                        AppTheme.accent.opacity(0.1)
                                    ]),
                                    center: .center
                                ),
                                style: StrokeStyle(lineWidth: 3.5, lineCap: .round)
                            )
                            .frame(width: 44, height: 44)
                            .rotationEffect(.degrees(rotation))
                    }

                    // Status Message
                    Text(statusMessages[statusIndex])
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundStyle(.white.opacity(0.75))
                        .animation(.easeInOut(duration: 0.25), value: statusIndex)

                    // Mini Progress Bar
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule()
                                .fill(Color.white.opacity(0.08))
                                .frame(height: 4)

                            Capsule()
                                .fill(
                                    LinearGradient(
                                        colors: [AppTheme.accent, Color(hue: 0.78, saturation: 0.9, brightness: 1.0)],
                                        startPoint: .leading,
                                        endPoint: .trailing
                                    )
                                )
                                .frame(width: geo.size.width * loadingProgress, height: 4)
                                .shadow(color: AppTheme.accent.opacity(0.8), radius: 6, y: 0)
                        }
                    }
                    .frame(width: 170, height: 4)
                }
                .padding(.bottom, 48)
            }
            .padding(.horizontal, 24)
        }
        .preferredColorScheme(.dark)
        .onAppear {
            // Spinner rotation
            withAnimation(.linear(duration: 1.2).repeatForever(autoreverses: false)) {
                rotation = 360
            }

            // Pulse effect on logo
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) {
                pulseScale = 1.05
            }

            // Progress bar animation
            withAnimation(.easeOut(duration: 1.7)) {
                loadingProgress = 1.0
            }

            // Cycle status messages
            Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { timer in
                if statusIndex < statusMessages.count - 1 {
                    statusIndex += 1
                } else {
                    timer.invalidate()
                }
            }
        }
    }
}
