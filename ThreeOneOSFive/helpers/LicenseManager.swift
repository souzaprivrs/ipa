import Combine
import Foundation
import Security
import UIKit

// API ZeroM$ Oficial (de auth.hpp)
private let kAPIBaseURL = "https://api.zeroms.shop"
private let kAPIKey = "zeroms_e520035f638c5658045d211ce1b26dc85cd60243bd8427cf09d0b60fae7f37ba"

@MainActor
final class LicenseManager: ObservableObject {

    @Published private(set) var isActive     = false
    @Published private(set) var isBusy       = false
    @Published private(set) var message: String?
    @Published private(set) var expiresAt: String?
    @Published private(set) var daysRemaining: Int?
    @Published var rememberKey = true

    private let service     = "com.ZeroM$.external-ios.activation"
    private let keyAccount  = "license-key"

    init() {
        // Inicia na tela de login para que o usuário possa autenticar
    }

    var hasRememberedKey: Bool {
        if let k = storedKey(), !k.isEmpty { return true }
        return false
    }

    func beginLaunchSession() {
        // Mantém na tela de login para validação explícita
    }

    func activate(key: String, isAutoLogin: Bool = false) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        Task { await verifyOnline(key: trimmed, silent: false) }
    }

    func rememberedKey() -> String? { storedKey() }

    func refresh() {
        guard let saved = storedKey(), !saved.isEmpty else { return }
        Task { await verifyOnline(key: saved, silent: false) }
    }

    func deactivate() {
        deleteKey()
        isActive      = false
        message       = nil
        expiresAt     = nil
        daysRemaining = nil
    }

    // MARK: - API ZeroM$

    // Chave master local — bypass para testes se necessário
    private let kMasterKey = "123"

    private func verifyOnline(key: String, silent: Bool) async {
        if !silent { isBusy = true }

        // --- BYPASS: chave master local ---
        if key == kMasterKey {
            isActive      = true
            expiresAt     = "Permanente (Master)"
            daysRemaining = nil
            if rememberKey { saveKey(key) }
            if !silent { message = "Key master ativada com sucesso!" }
            if !silent { isBusy = false }
            return
        }
        // ----------------------------------

        let deviceID = UIDevice.current.identifierForVendor?.uuidString ?? "ZeroM$-iOS"
        let body: [String: Any] = [
            "key": key,
            "hwid": deviceID,
            "apiKey": kAPIKey,
            "username": "",
            "password": ""
        ]

        guard let url = URL(string: "\(kAPIBaseURL)/api/licenses/validate"),
              let bodyData = try? JSONSerialization.data(withJSONObject: body) else {
            if !silent { message = "Erro ao estruturar requisição" }
            if !silent { isBusy = false }
            return
        }

        var req = URLRequest(url: url, timeoutInterval: 15)
        req.httpMethod = "POST"
        req.httpBody   = bodyData
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(kAPIKey, forHTTPHeaderField: "X-API-Key")
        req.setValue("https://zeroms.shop", forHTTPHeaderField: "Origin")
        req.setValue("https://zeroms.shop/", forHTTPHeaderField: "Referer")
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            let httpResponse = response as? HTTPURLResponse
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

            let success = (json?["success"] as? Bool) ?? (httpResponse?.statusCode == 200)

            if success {
                isActive = true
                if let exp = json?["expiresAt"] as? String {
                    expiresAt = exp
                    message = "Key válida — Expira em: \(exp)"
                } else {
                    expiresAt = "Vitalícia / Ativa"
                    message = "Key ativada com sucesso!"
                }

                if rememberKey { saveKey(key) }
            } else {
                let errCode = json?["error"] as? String ?? ""
                let errMsg: String
                switch errCode {
                case "key_not_found", "user_not_found":
                    errMsg = "Key não encontrada! Verifique o que digitou."
                case "hwid_mismatch":
                    errMsg = "Key já vinculada a outro dispositivo."
                case "subscription_expired", "license_expired":
                    errMsg = "Esta licença está expirada."
                case "key_already_used":
                    errMsg = "Key já está em uso."
                case "too_many_attempts", "too_many_requests":
                    errMsg = "Muitas tentativas! Aguarde 1 minuto."
                default:
                    errMsg = json?["message"] as? String ?? "Licença inválida ou incorreta."
                }

                if !silent { message = errMsg }
                deleteKey()
                isActive = false
            }
        } catch {
            if !silent { message = "Sem conexão com o servidor ZeroM$" }
        }

        if !silent { isBusy = false }
    }

    // MARK: - Keychain

    private func storedKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func saveKey(_ value: String) {
        let base: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String]      = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func deleteKey() {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
}
