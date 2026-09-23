import SwiftUI

struct LicenseActivationView: View {
    @ObservedObject var manager: LicenseManager
    @State private var key = ""
    @FocusState private var keyFocused: Bool

    var body: some View {
        NavigationStack {
            ZStack {
                AnimatedHyperBackdrop().ignoresSafeArea()
                Color.black.opacity(0.18).ignoresSafeArea()
                ScrollViewReader { proxy in
                    ScrollView(showsIndicators: false) {
                        VStack(spacing: 0) {
                            Spacer(minLength: 42)
                            headerSection
                            cardSection
                                .id("activation-card")
                            Spacer(minLength: 42)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.bottom, 28)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onChange(of: keyFocused) { focused in
                        guard focused else { return }
                        withAnimation(.easeOut(duration: 0.25)) {
                            proxy.scrollTo("activation-card", anchor: .center)
                        }
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
        .onAppear {
            if let saved = manager.rememberedKey(), key.isEmpty {
                key = saved
            }
        }
    }

    // MARK: - Sections

    private var headerSection: some View {
        VStack(spacing: 8) {
            BrandLogoView(height: 52)
            Text("Version: 1.1.0")
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.55))
            Text("Package: ZeroM$")
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(AppTheme.secondaryAccent.opacity(0.9))
                .padding(.top, 3)
        }
    }

    private var cardSection: some View {
        VStack(spacing: 16) {
            titleRow
            subtitleText
            keyInput
            rememberToggle
            actionButton
            statusMessage
        }
        .padding(20)
        .background(.ultraThinMaterial.opacity(0.72), in: RoundedRectangle(cornerRadius: 25, style: .continuous))
        .background(Color.gray.opacity(0.18), in: RoundedRectangle(cornerRadius: 25, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 25, style: .continuous).stroke(Color.white.opacity(0.16), lineWidth: 1))
        .padding(.horizontal, 22)
        .padding(.top, 26)
    }

    private var titleRow: some View {
        HStack(spacing: 10) {
            Image(systemName: manager.isBusy ? "arrow.triangle.2.circlepath" : (manager.isKeyValidated ? "checkmark.shield.fill" : "key.fill"))
                .foregroundStyle(manager.isKeyValidated ? Color.green : AppTheme.accent)
                .font(.system(size: 16, weight: .bold))
            Text(manager.isBusy ? "Conectando ao ZeroM$..." : (manager.isKeyValidated ? "Licença Ativa" : "Licença ZeroM$"))
                .font(.system(size: 16, weight: .black, design: .rounded))
                .foregroundStyle(.white)
            Spacer()
        }
    }

    private var subtitleText: some View {
        Text(manager.isKeyValidated ? "Sua chave de licença está validada. Pressione entrar para acessar." : "Digite sua chave de licença para ativar o ZeroM$")
            .font(.system(size: 13, weight: .medium, design: .rounded))
            .foregroundStyle(.white.opacity(0.68))
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var keyInput: some View {
        HStack(spacing: 8) {
            TextField("Chave de licença", text: $key)
                .focused($keyFocused)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.done)
                .onSubmit {
                    if manager.isKeyValidated {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            manager.enterApp()
                        }
                    } else {
                        activate()
                    }
                }
                .onChange(of: key) { _ in
                    if manager.isKeyValidated {
                        manager.resetValidation()
                    }
                }
                .font(.system(size: 16, weight: .medium, design: .monospaced))
                .foregroundStyle(.white)

            if manager.isKeyValidated {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.system(size: 18, weight: .bold))
            }
        }
        .padding(.horizontal, 16)
        .frame(height: 54)
        .background(Color.gray.opacity(0.22), in: RoundedRectangle(cornerRadius: 17, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .stroke(manager.isKeyValidated ? Color.green.opacity(0.65) : AppTheme.accent.opacity(0.48), lineWidth: 1)
        )
    }

    private var rememberToggle: some View {
        Toggle("Lembrar chave neste dispositivo", isOn: $manager.rememberKey)
            .font(.system(size: 12, weight: .bold, design: .rounded))
            .foregroundStyle(.white.opacity(0.72))
            .tint(AppTheme.accent)
    }

    private var actionButton: some View {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        let disabled = trimmed.isEmpty || manager.isBusy

        return Group {
            if manager.isKeyValidated {
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        manager.enterApp()
                    }
                }) {
                    HStack(spacing: 10) {
                        Image(systemName: "arrow.right.circle.fill")
                            .font(.system(size: 17, weight: .bold))
                        Text("ENTRAR NO APP")
                    }
                    .font(.system(size: 15, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 54)
                    .background(
                        LinearGradient(
                            colors: [AppTheme.accent, Color(hue: 0.78, saturation: 0.9, brightness: 0.9)],
                            startPoint: .leading,
                            endPoint: .trailing
                        ),
                        in: RoundedRectangle(cornerRadius: 17, style: .continuous)
                    )
                    .shadow(color: AppTheme.accent.opacity(0.45), radius: 14, y: 7)
                }
                .buttonStyle(.plain)
            } else {
                Button(action: activate) {
                    HStack(spacing: 9) {
                        Image(systemName: manager.isBusy ? "hourglass" : "checkmark.shield.fill")
                        Text(manager.isBusy ? "VERIFICANDO COM ZEROM$..." : "VALIDAR KEY")
                    }
                    .font(.system(size: 14, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 54)
                    .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 17, style: .continuous))
                    .shadow(color: AppTheme.accent.opacity(0.30), radius: 14, y: 7)
                }
                .buttonStyle(.plain)
                .disabled(disabled)
                .opacity(disabled ? 0.48 : 1)
            }
        }
    }

    @ViewBuilder
    private var statusMessage: some View {
        if manager.isKeyValidated {
            VStack(spacing: 4) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                    Text("KEY VALIDADA COM SUCESSO!")
                        .font(.system(size: 12, weight: .heavy, design: .rounded))
                        .foregroundStyle(.green)
                }
                if let exp = manager.expiresAt {
                    Text("Status: \(exp)")
                        .font(.system(size: 11, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white.opacity(0.75))
                }
                Text("Toque em ENTRAR NO APP para acessar o painel.")
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.6))
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color.green.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Color.green.opacity(0.3), lineWidth: 1))
        } else if let msg = manager.message {
            Text(msg)
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(Color.red.opacity(0.95))
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Color.gray.opacity(0.20), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        }
    }

    // MARK: - Helpers

    private func activate() {
        keyFocused = false
        manager.activate(key: key)
    }
}
