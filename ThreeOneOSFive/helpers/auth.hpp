#pragma once
#include <string>
#include <windows.h>
#include <wininet.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <random>
#include <wincrypt.h>
#include <fstream>
#include <chrono>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdio>
#include <algorithm>
#include <limits>
#include <cctype>
#include <cstdlib>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// Constantes de configuracao
namespace AuthConfig {
    constexpr int DEFAULT_MAX_RETRIES = 5;           // 5 retries para tolerar redes asiáticas/proxies instáveis
    constexpr int DEFAULT_RETRY_DELAY_MS = 1000;     // 1s base — backoff exponencial: 1s, 2s, 4s, 8s, 16s
    constexpr int DEFAULT_REQUEST_TIMEOUT_MS = 30000; // 30s por tentativa (antes 15s, insuficiente para Ásia↔EUA com proxy)
    // 30s e nao 60s: o servidor considera o usuario offline apos 90s sem sinal
    // (APP_USER_ONLINE_TIMEOUT_MS). Com 60s, um unico heartbeat que falhe ou
    // demore (timeout de 30s por tentativa) ja estoura a janela e o usuario
    // desaparece do painel Online. Com 30s cabem 3 tentativas dentro da janela.
    // Limite do servidor: 30 requisicoes / 2 min por token — 30s deixa folga.
    constexpr int DEFAULT_HEARTBEAT_INTERVAL_SEC = 30;
    constexpr int CACHE_DEFAULT_DAYS = 30;
    constexpr size_t SHA256_BLOCK_SIZE = 64;
    constexpr size_t SHA256_HASH_SIZE = 32;
    constexpr int MAX_DRIFT_MS = 300000; // 5 minutos
}

// ============================================================
// Implementacao SHA256 100% software - sem depender de CryptAPI
// Garante resultados identicos em TODOS os sistemas Windows
// ============================================================
namespace SoftwareSHA256 {

    struct SHA256Context {
        uint32_t state[8];
        uint64_t bitcount;
        uint8_t buffer[64];
    };

    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    inline uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    inline uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    inline uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    inline void transform(SHA256Context& ctx, const uint8_t* data) {
        uint32_t W[64];
        for (int i = 0; i < 16; i++) {
            W[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
                ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
        }

        uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
        uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
        ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
    }

    inline void init(SHA256Context& ctx) {
        ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
        ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
        ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
        ctx.bitcount = 0;
        memset(ctx.buffer, 0, 64);
    }

    inline void update(SHA256Context& ctx, const uint8_t* data, size_t len) {
        size_t bufferFill = (size_t)(ctx.bitcount >> 3) & 63;
        ctx.bitcount += (uint64_t)len << 3;

        if (bufferFill > 0) {
            size_t space = 64 - bufferFill;
            if (len >= space) {
                memcpy(ctx.buffer + bufferFill, data, space);
                transform(ctx, ctx.buffer);
                data += space;
                len -= space;
                bufferFill = 0;
            }
            else {
                memcpy(ctx.buffer + bufferFill, data, len);
                return;
            }
        }

        while (len >= 64) {
            transform(ctx, data);
            data += 64;
            len -= 64;
        }

        if (len > 0) {
            memcpy(ctx.buffer, data, len);
        }
    }

    inline void finalize(SHA256Context& ctx, uint8_t hash[32]) {
        size_t bufferFill = (size_t)(ctx.bitcount >> 3) & 63;
        ctx.buffer[bufferFill++] = 0x80;

        if (bufferFill > 56) {
            memset(ctx.buffer + bufferFill, 0, 64 - bufferFill);
            transform(ctx, ctx.buffer);
            bufferFill = 0;
        }

        memset(ctx.buffer + bufferFill, 0, 56 - bufferFill);

        uint64_t bits = ctx.bitcount;
        for (int i = 7; i >= 0; i--) {
            ctx.buffer[56 + (7 - i)] = (uint8_t)(bits >> (i * 8));
        }

        transform(ctx, ctx.buffer);

        for (int i = 0; i < 8; i++) {
            hash[i * 4] = (uint8_t)(ctx.state[i] >> 24);
            hash[i * 4 + 1] = (uint8_t)(ctx.state[i] >> 16);
            hash[i * 4 + 2] = (uint8_t)(ctx.state[i] >> 8);
            hash[i * 4 + 3] = (uint8_t)(ctx.state[i]);
        }
    }

    // Calcula SHA256 de dados binarios (suporta null bytes)
    inline std::string hashBinary(const uint8_t* data, size_t len) {
        SHA256Context ctx;
        init(ctx);
        update(ctx, data, len);
        uint8_t hash[32];
        finalize(ctx, hash);

        std::stringstream ss;
        for (int i = 0; i < 32; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    // Calcula SHA256 de uma string
    inline std::string hash(const std::string& data) {
        return hashBinary((const uint8_t*)data.data(), data.size());
    }

    // HMAC-SHA256 (RFC 2104) - 100% compativel com Node.js crypto
    inline std::string hmac(const std::string& keyStr, const std::string& message) {
        constexpr size_t blockSize = 64;
        std::vector<uint8_t> key;

        // Se a chave for maior que o block size, hash dela
        if (keyStr.size() > blockSize) {
            std::string keyHash = hash(keyStr);
            for (size_t i = 0; i < keyHash.length(); i += 2) {
                key.push_back((uint8_t)strtol(keyHash.substr(i, 2).c_str(), nullptr, 16));
            }
        }
        else {
            key.assign(keyStr.begin(), keyStr.end());
        }

        // Pad com zeros
        while (key.size() < blockSize) key.push_back(0);

        // i_key_pad e o_key_pad
        std::vector<uint8_t> i_key_pad(blockSize);
        std::vector<uint8_t> o_key_pad(blockSize);
        for (size_t i = 0; i < blockSize; i++) {
            i_key_pad[i] = key[i] ^ 0x36;
            o_key_pad[i] = key[i] ^ 0x5c;
        }

        // inner = hash(i_key_pad + message)
        std::vector<uint8_t> innerInput(i_key_pad.begin(), i_key_pad.end());
        innerInput.insert(innerInput.end(), (uint8_t*)message.data(), (uint8_t*)message.data() + message.size());
        std::string innerHash = hashBinary(innerInput.data(), innerInput.size());

        // Converter inner hash hex para bytes
        std::vector<uint8_t> innerHashBytes;
        for (size_t i = 0; i < innerHash.length(); i += 2) {
            innerHashBytes.push_back((uint8_t)strtol(innerHash.substr(i, 2).c_str(), nullptr, 16));
        }

        // outer = hash(o_key_pad + innerHashBytes)
        std::vector<uint8_t> outerInput(o_key_pad.begin(), o_key_pad.end());
        outerInput.insert(outerInput.end(), innerHashBytes.begin(), innerHashBytes.end());

        return hashBinary(outerInput.data(), outerInput.size());
    }
} // namespace SoftwareSHA256

// Enum para tipos de erro
enum class AuthErrorType {
    NONE,
    NETWORK_ERROR,
    TIMEOUT,
    SERVER_OFFLINE,
    INVALID_RESPONSE,
    AUTH_FAILED,
    RATE_LIMITED
};

// Estrutura para cache offline
struct OfflineCache {
    std::string username;
    std::string hwid;
    uint64_t expirationTime;
    bool isValid;
};

class Auth {
private:
    // Configuracões da API
    std::string api_host = "api.zeroms.shop";
    INTERNET_PORT api_port = INTERNET_DEFAULT_HTTPS_PORT;
    bool api_use_https = true;
    std::string api_base_path = "/api/app-users";
    std::string api_key;   // Application API Key (appSecret)
    std::string owner_id;  // ID do dono da aplicação no painel ZeroM$
    std::string app_name;  // Nome escolhido pelo usuário ao criar a aplicação na ZeroM$
    std::string version;
    std::string session_id;
    std::string session_token;

    // Configuracões de retry (otimizado com constantes)
    int max_retries = AuthConfig::DEFAULT_MAX_RETRIES;
    int retry_delay_ms = AuthConfig::DEFAULT_RETRY_DELAY_MS;
    int request_timeout_ms = AuthConfig::DEFAULT_REQUEST_TIMEOUT_MS;

    // Cache offline
    OfflineCache offline_cache;
    std::string cache_file = "auth_cache.dat";
    AuthErrorType last_error = AuthErrorType::NONE;
    std::mutex cache_mutex; // Thread-safe para cache

    // Configuracões de seguranca
    bool enforce_online_validation = false;
    std::atomic<bool> authenticated;

    // Sistema de heartbeat (otimizado com atomic)
    std::atomic<bool> heartbeat_running;
    std::thread heartbeat_thread;
    std::atomic<int> heartbeat_interval_seconds;
    std::atomic<bool> force_exit_on_offline;
    std::string current_username;
    std::string current_hwid;
    std::mutex heartbeat_mutex; // Thread-safe para heartbeat
    std::atomic<int> consecutive_failures; // Contador de falhas consecutivas
    int max_consecutive_failures = 5; // Fecha apos 5 falhas seguidas (5min com heartbeat de 60s)
    std::function<void()> offline_handler; // Callback para lidar com servidor offline
    std::atomic<bool> server_online; // Estado atual do servidor
    std::atomic<bool> offline_triggered; // Garante que a acao de offline ocorre apenas uma vez por evento
    uint64_t last_expiration_ms = 0; // Expiracao convertida para ms (quando disponivel)
    std::string last_expiry_raw; // Texto bruto retornado pela API
    std::string last_hwid;

    // Monitor paralelo semelhante ao "Real" (ping em /api/time)
    std::atomic<bool> monitor_running;
    std::thread monitor_thread;

    // Monitor de versão - verifica atualizações enquanto logado
    std::atomic<bool> version_monitor_running;
    std::thread version_monitor_thread;
    std::function<void(const std::string&, const std::string&)> version_update_handler;
    std::atomic<bool> version_outdated; // Flag para indicar que versão está desatualizada
    std::string update_download_url; // URL de download da nova versão
    std::string latest_version; // Última versão disponível

    // Sistema de detecção de peers (outros usuários Zero no mesmo servidor)
    std::atomic<bool> peer_polling_running{false};
    std::thread peer_polling_thread;
    std::vector<std::string> peer_list;
    std::mutex peer_list_mutex;
    std::string current_server_identifier;
    std::mutex server_id_mutex;
    std::function<void(const std::vector<std::string>&)> peer_update_callback;
    std::function<std::string()> server_identifier_provider;
    std::function<std::string()> display_name_provider;
    std::function<bool()> peer_detection_provider; // Retorna true se PeerDetection estiver ativado

    // Escape básico para valores JSON (aspas e backslash)
    static std::string escapeJson(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else out += c;
        }
        return out;
    }

    // Funcao auxiliar para gerar nonce aleatório
    std::string generateNonce() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << std::setw(16) << dis(gen);
        ss << std::setw(16) << dis(gen);
        return ss.str();
    }

    // SHA256 - usa implementacao 100% software (sem CryptAPI)
    // Garante resultado identico em TODOS os PCs, sem depender do estado do Windows
    std::string sha256(const std::string& data) {
        return SoftwareSHA256::hash(data);
    }

    // HMAC-SHA256 - usa implementacao 100% software (RFC 2104)
    // Garante compatibilidade total com Node.js crypto.createHmac('sha256', ...)
    std::string hmacSha256(const std::string& key, const std::string& data) {
        return SoftwareSHA256::hmac(key, data);
    }

    // Funcao para obter timestamp atual em milissegundos
    std::string getCurrentTimestamp() const {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);

        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;

        // Converter de 100-nanosegundos desde 1601 para milissegundos desde 1970
        uint64_t ms = (uli.QuadPart / 10000ULL) - 11644473600000ULL;

        std::stringstream ss;
        ss << ms;
        return ss.str();
    }

    // Funcao para obter timestamp em uint64
    uint64_t getCurrentTimestampUint64() const {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);

        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;

        return (uli.QuadPart / 10000ULL) - 11644473600000ULL;
    }

    // Funcao XOR simples para ofuscar cache
    std::string xorEncrypt(const std::string& data, const std::string& key) {
        std::string result = data;
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    // Salvar cache offline (thread-safe)
    void saveOfflineCache(const std::string& username, const std::string& hwid, uint64_t expirationTime) {
        std::lock_guard<std::mutex> lock(cache_mutex);

        try {
            std::ofstream file(cache_file, std::ios::binary);
            if (!file.is_open()) {
                OutputDebugStringA("[Cache] Erro ao abrir arquivo\n");
                return;
            }

            std::string data = username + "|" + hwid + "|" + std::to_string(expirationTime);
            std::string encrypted = xorEncrypt(data, api_key);
            file.write(encrypted.c_str(), encrypted.size());
            file.close();

            // Atualizar cache em memória
            offline_cache.username = username;
            offline_cache.hwid = hwid;
            offline_cache.expirationTime = expirationTime;
            offline_cache.isValid = true;

            OutputDebugStringA("[Cache] Sessao salva\n");
        }
        catch (const std::exception& e) {
            OutputDebugStringA(("[Cache] Excecao: " + std::string(e.what()) + "\n").c_str());
        }
    }

    // Carregar cache offline (thread-safe e otimizado)
    bool loadOfflineCache() {
        std::lock_guard<std::mutex> lock(cache_mutex);

        try {
            std::ifstream file(cache_file, std::ios::binary);
            if (!file.is_open()) {
                offline_cache.isValid = false;
                return false;
            }

            std::string encrypted((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            if (encrypted.empty()) {
                offline_cache.isValid = false;
                return false;
            }

            std::string data = xorEncrypt(encrypted, api_key);

            size_t pos1 = data.find('|');
            size_t pos2 = data.find('|', pos1 + 1);

            if (pos1 == std::string::npos || pos2 == std::string::npos) {
                OutputDebugStringA("[Cache] Formato invalido, deletando cache corrompido\n");
                offline_cache.isValid = false;
                std::remove(cache_file.c_str()); // Deletar cache corrompido
                return false;
            }

            offline_cache.username = data.substr(0, pos1);
            offline_cache.hwid = data.substr(pos1 + 1, pos2 - pos1 - 1);

            // Validar que expirationTime e um numero
            std::string expStr = data.substr(pos2 + 1);
            if (expStr.empty() || !std::all_of(expStr.begin(), expStr.end(), ::isdigit)) {
                OutputDebugStringA("[Cache] Expiration invalida, deletando cache\n");
                offline_cache.isValid = false;
                std::remove(cache_file.c_str());
                return false;
            }

            offline_cache.expirationTime = std::stoull(expStr);

            // Validar que username e hwid nao estao vazios
            if (offline_cache.username.empty() || offline_cache.hwid.empty()) {
                OutputDebugStringA("[Cache] Dados vazios, deletando cache\n");
                offline_cache.isValid = false;
                std::remove(cache_file.c_str());
                return false;
            }

            offline_cache.isValid = true;

            OutputDebugStringA("[Cache] Carregado com sucesso\n");
            return true;

        }
        catch (const std::exception& e) {
            OutputDebugStringA(("[Cache] Erro ao carregar: " + std::string(e.what()) + "\n").c_str());
            offline_cache.isValid = false;
            // Deletar cache corrompido para evitar erros futuros
            std::remove(cache_file.c_str());
            return false;
        }
    }

    // Verificar se cache offline ainda e valido
    bool isOfflineCacheValid(const std::string& hwid) {
        if (!offline_cache.isValid) return false;

        uint64_t currentTime = getCurrentTimestampUint64();

        // Verificar HWID
        if (offline_cache.hwid != hwid) {
            OutputDebugStringA("[Cache] HWID nao corresponde\n");
            return false;
        }

        // Verificar expiracao
        if (currentTime > offline_cache.expirationTime) {
            OutputDebugStringA("[Cache] Cache expirado\n");
            return false;
        }

        return true;
    }

    // Obter mensagem de erro amigavel
    std::string getErrorMessage(AuthErrorType errorType) const {
        switch (errorType) {
        case AuthErrorType::NETWORK_ERROR:
            return "Erro de conexao com a internet. Verifique sua rede.";
        case AuthErrorType::TIMEOUT:
            return "Tempo de conexao esgotado. Servidor pode estar lento.";
        case AuthErrorType::SERVER_OFFLINE:
            return "Servidor de autenticacao offline. Tente novamente mais tarde.";
        case AuthErrorType::INVALID_RESPONSE:
            return "Resposta invalida do servidor.";
        case AuthErrorType::AUTH_FAILED:
            return "Autenticacao falhou. Verifique suas credenciais.";
        case AuthErrorType::RATE_LIMITED:
            return "Muitas tentativas. Aguarde um momento.";
        default:
            return "Erro desconhecido.";
        }
    }

    // Helper HTTP para API ZeroM$ (x-api-key e opcional bearer token)
    // maxAttempts: 0 = usar max_retries padrão; >0 = limitar tentativas
    std::string makeHttpRequest(const std::string& method, const std::string& path, const std::string& data, bool includeSessionToken = false, int maxAttempts = 0) {
        OutputDebugStringA(("========== HTTP REQUEST START: " + method + " " + path + " ==========\n").c_str());
        last_error = AuthErrorType::NONE;

        // Snapshot do token sob lock — evita data race com login() que escreve session_token
        std::string tokenSnapshot;
        if (includeSessionToken) {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            tokenSnapshot = session_token;
        }

        int retries = (maxAttempts > 0) ? (maxAttempts - 1) : max_retries;
        for (int attempt = 0; attempt <= retries; attempt++) {
            if (attempt > 0) {
                int delay = retry_delay_ms * (1 << (attempt - 1)); // Backoff exponencial
                OutputDebugStringA(("[Retry] Tentativa " + std::to_string(attempt + 1) + "/" + std::to_string(max_retries + 1) + " em " + std::to_string(delay) + "ms\n").c_str());
                Sleep(delay);
            }

            // Estratégia de fallback inteligente:
            // 1ª tentativa: PRECONFIG (respeita proxy do sistema - resolve ambientes corporativos)
            // 2ª tentativa: DIRECT (bypass proxy - resolve casos com proxy mal configurado)
            //
            // User-Agent COMPLETO de Chrome real — UAs incompletos (sem Chrome/Safari token)
            // são marcados como bot pelo Cloudflare Bot Management em regiões de alto risco
            // (Ásia, leste europeu), retornando HTML challenge em vez de JSON.
            static const char* kUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            OutputDebugStringA("[WinInet] Tentando conectar via PRECONFIG...\n");
            HINTERNET hInternet = InternetOpenA(kUserAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
            if (!hInternet) {
                DWORD preconfig_error = GetLastError();
                OutputDebugStringA(("[WinInet] PRECONFIG falhou (codigo: " + std::to_string(preconfig_error) + "), tentando DIRECT...\n").c_str());
                
                // Fallback para DIRECT se PRECONFIG falhar
                hInternet = InternetOpenA(kUserAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                if (!hInternet) {
                    DWORD direct_error = GetLastError();
                    last_error = AuthErrorType::NETWORK_ERROR;
                    OutputDebugStringA(("[Error] Falha ao inicializar WinInet - PRECONFIG: " + std::to_string(preconfig_error) + ", DIRECT: " + std::to_string(direct_error) + "\n").c_str());
                    continue;
                } else {
                    OutputDebugStringA("[WinInet] Conectado via DIRECT (bypass proxy)\n");
                }
            } else {
                OutputDebugStringA("[WinInet] Conectado via PRECONFIG (usando configuracoes do sistema)\n");
            }

            // Configurar timeouts no handle raiz (herdado pelos handles filhos)
            DWORD timeout = request_timeout_ms;
            InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
            InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
            InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

            HINTERNET hConnect = InternetConnectA(hInternet, api_host.c_str(), api_port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (!hConnect) {
                DWORD error = GetLastError();
                std::string errorMsg;
                
                // Mensagens específicas para erros comuns de conexão
                switch (error) {
                    case ERROR_INTERNET_NAME_NOT_RESOLVED:
                        errorMsg = "DNS Error: Nao foi possivel resolver o nome do servidor. Verifique sua conexao com a internet.";
                        last_error = AuthErrorType::NETWORK_ERROR;
                        break;
                    case ERROR_INTERNET_CANNOT_CONNECT:
                        errorMsg = "Nao foi possivel conectar ao servidor. Verifique se sua internet esta funcionando.";
                        last_error = AuthErrorType::SERVER_OFFLINE;
                        break;
                    case ERROR_INTERNET_CONNECTION_ABORTED:
                        errorMsg = "Conexao abortada. Firewall ou antivirus pode estar bloqueando.";
                        last_error = AuthErrorType::NETWORK_ERROR;
                        break;
                    case ERROR_INTERNET_CONNECTION_RESET:
                        errorMsg = "Conexao resetada. Firewall ou proxy pode estar interferindo.";
                        last_error = AuthErrorType::NETWORK_ERROR;
                        break;
                    case ERROR_INTERNET_TIMEOUT:
                        errorMsg = "Timeout ao conectar. Servidor pode estar indisponivel ou sua conexao esta lenta.";
                        last_error = AuthErrorType::TIMEOUT;
                        break;
                    default:
                        errorMsg = "Falha ao conectar ao servidor (codigo: " + std::to_string(error) + ")";
                        last_error = AuthErrorType::SERVER_OFFLINE;
                        break;
                }
                
                OutputDebugStringA(("[Error] " + errorMsg + "\n").c_str());
                InternetCloseHandle(hInternet);
                
                // Erro de DNS: tentar novamente (pode ser falha temporária do resolver)
                // Não lançar exceção — deixar o retry normal funcionar
                if (error == ERROR_INTERNET_NAME_NOT_RESOLVED) {
                    last_error = AuthErrorType::NETWORK_ERROR;
                    OutputDebugStringA(("[Error] DNS falhou, vai tentar novamente: " + errorMsg + "\n").c_str());
                }
                continue;
            }

            DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
            if (api_use_https) {
                flags |= INTERNET_FLAG_SECURE
                      |  INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                      |  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
            }

            HINTERNET hRequest = HttpOpenRequestA(hConnect, method.c_str(), path.c_str(), NULL, NULL, NULL, flags, 0);
            if (!hRequest) {
                last_error = AuthErrorType::NETWORK_ERROR;
                OutputDebugStringA("[Error] Falha ao criar requisicao HTTP\n");
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                continue;
            }

            // Habilitar descompressão automática de gzip/deflate.
            // Cloudflare comprime respostas mesmo com Accept-Encoding: identity em algumas regiões.
            // Sem essa flag, WinInet entrega o body comprimido (binário) e o parser JSON falha.
            // INTERNET_OPTION_HTTP_DECODING (65) — disponível em Windows 7+
            #ifndef INTERNET_OPTION_HTTP_DECODING
            #define INTERNET_OPTION_HTTP_DECODING 65
            #endif
            DWORD decoding = 1;
            InternetSetOptionA(hRequest, INTERNET_OPTION_HTTP_DECODING, &decoding, sizeof(decoding));

            // Aplicar timeouts também no hRequest para garantir que o TLS handshake
            // e a leitura da resposta respeitem o timeout (HTTPS requer isso explicitamente)
            InternetSetOptionA(hRequest, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
            InternetSetOptionA(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
            InternetSetOptionA(hRequest, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

            // Ler flags de segurança existentes e adicionar os de ignore via OR
            // (não substituir, para não remover proteções necessárias para a conexão TLS)
            DWORD secFlags = 0;
            DWORD secFlagsSize = sizeof(secFlags);
            if (!InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &secFlagsSize)) {
                secFlags = 0;
            }
            secFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA
                     |  SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                     |  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                     |  SECURITY_FLAG_IGNORE_REVOCATION
                     |  SECURITY_FLAG_IGNORE_WRONG_USAGE;
            InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
            OutputDebugStringA("[WinInet] Flags de seguranca SSL configuradas (ignore all)\n");

            // Headers de browser real para passar pelo Cloudflare Bot Management.
            // Cloudflare avalia o conjunto: presença de Accept/Accept-Language/Accept-Encoding,
            // User-Agent fingerprint, e padrão TLS. Em regiões de alto risco (Ásia/Japão),
            // a ausência destes headers basta para retornar HTML challenge em vez do JSON da API.
            std::string headers = "Content-Type: application/json\r\n";
            headers += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n";
            headers += "Accept: application/json, text/plain, */*\r\n";
            headers += "Accept-Language: en-US,en;q=0.9\r\n";
            headers += "Accept-Encoding: gzip, deflate\r\n"; // Browser real envia isso; WinInet descomprime via INTERNET_OPTION_HTTP_DECODING setado acima
            headers += "Origin: https://zeroms.shop\r\n";
            headers += "Referer: https://zeroms.shop/\r\n";
            headers += "Sec-Fetch-Site: same-site\r\n";
            headers += "Sec-Fetch-Mode: cors\r\n";
            headers += "Sec-Fetch-Dest: empty\r\n";
            if (!api_key.empty()) {
                headers += "X-API-Key: " + api_key + "\r\n";
            }
            if (includeSessionToken && !tokenSnapshot.empty()) {
                headers += "Authorization: Bearer " + tokenSnapshot + "\r\n";
            }

            if (!HttpAddRequestHeadersA(hRequest, headers.c_str(), -1, HTTP_ADDREQ_FLAG_ADD)) {
                DWORD error = GetLastError();
                OutputDebugStringA(("[ERROR] Falha ao adicionar headers. Codigo: " + std::to_string(error) + "\n").c_str());
            }

            LPVOID bodyPtr = data.empty() ? NULL : (LPVOID)data.c_str();
            DWORD bodyLen = static_cast<DWORD>(data.length());

            if (!HttpSendRequestA(hRequest, NULL, 0, bodyPtr, bodyLen)) {
                DWORD error = GetLastError();
                if (error == ERROR_INTERNET_TIMEOUT) {
                    last_error = AuthErrorType::TIMEOUT;
                    OutputDebugStringA("[Error] Timeout na requisicao\n");
                }
                // Erros de SSL/certificado — pode ser proxy interceptando TLS (comum em ISPs asiáticos),
                // relógio desincronizado, ou antivírus com inspeção SSL.
                // As flags SECURITY_FLAG_IGNORE_* já estão setadas acima, mas em alguns casos o
                // HttpSendRequest ainda falha antes de as flags surtirem efeito (race no WinInet).
                // Solução: continuar com retry — na próxima tentativa as flags já estarão aplicadas.
                else if (error == ERROR_INTERNET_SEC_CERT_DATE_INVALID || 
                         error == ERROR_INTERNET_INVALID_CA ||
                         error == ERROR_INTERNET_SEC_CERT_ERRORS ||
                         error == ERROR_INTERNET_SEC_CERT_CN_INVALID ||
                         error == ERROR_INTERNET_SEC_CERT_REV_FAILED) {
                    last_error = AuthErrorType::SERVER_OFFLINE;
                    OutputDebugStringA(("[Error] Falha de SSL/Certificado, tentando novamente. Codigo: " + std::to_string(error) + "\n").c_str());
                    InternetCloseHandle(hRequest);
                    InternetCloseHandle(hConnect);
                    InternetCloseHandle(hInternet);
                    continue;
                }
                else {
                    last_error = AuthErrorType::NETWORK_ERROR;
                    OutputDebugStringA(("[Error] Falha ao enviar requisicao. Codigo: " + std::to_string(error) + "\n").c_str());
                }
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                continue;
            }

            // Verificar status code HTTP
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL);

            if (statusCode == 429) {
                last_error = AuthErrorType::RATE_LIMITED;
                OutputDebugStringA("[Error] Rate limited pelo servidor\n");
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                continue;
            }

            // Read response
            std::string response;
            char buffer[1024];
            DWORD bytesRead;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                response.append(buffer, bytesRead);
            }

            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);

            if (!response.empty()) {
                OutputDebugStringA(("[Response] Status Code: " + std::to_string(statusCode) + "\n").c_str());
                OutputDebugStringA(("[Response] Body: " + response + "\n").c_str());

                // Detecção de bloqueio por WAF/Cloudflare: resposta NÃO é JSON.
                // Quando o Cloudflare considera a requisição suspeita (User-Agent ruim,
                // IP em região de risco, fingerprint TLS atípico), ele retorna HTML
                // de challenge ou página de bloqueio em vez do JSON da API.
                // Sem essa checagem, o parser não acha "success" nem "error" e cai no
                // fallback genérico "Falha na autenticacao".
                {
                    // Pular espaços iniciais
                    size_t firstNonSpace = response.find_first_not_of(" \t\r\n");
                    if (firstNonSpace != std::string::npos) {
                        char first = response[firstNonSpace];
                        bool looksLikeJson = (first == '{' || first == '[');
                        if (!looksLikeJson) {
                            // Resposta não é JSON — provavelmente HTML de WAF
                            last_error = AuthErrorType::SERVER_OFFLINE;
                            std::string snippet = response.substr(firstNonSpace, 80);
                            OutputDebugStringA(("[Error] Resposta nao-JSON (provavel bloqueio WAF/Cloudflare). Inicio: " + snippet + "\n").c_str());
                            continue; // Tentar de novo (pode ser bloqueio temporário)
                        }
                    }
                }

                last_error = AuthErrorType::NONE;
                return response;
            }
            else {
                last_error = AuthErrorType::INVALID_RESPONSE;
                OutputDebugStringA("[Error] Resposta vazia do servidor\n");
            }
        }

        OutputDebugStringA("[Error] Todas as tentativas falharam\n");
        return "";
    }

    // Simple JSON value extractor
    std::string getJsonValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\":\"";
        size_t start = json.find(searchKey);
        if (start == std::string::npos) {
            // Try without quotes (for status, null, numbers)
            searchKey = "\"" + key + "\":";
            start = json.find(searchKey);
            if (start == std::string::npos) return "";
            start += searchKey.length();
            // Skip whitespace after colon
            while (start < json.size() && (json[start] == ' ' || json[start] == '\t')) ++start;
            size_t endComma = json.find(",", start);
            size_t endBrace = json.find("}", start);
            size_t end = (std::min)(
                endComma != std::string::npos ? endComma : json.size(),
                endBrace != std::string::npos ? endBrace : json.size());
            if (end >= json.size()) return "";
            return json.substr(start, end - start);
        }

        start += searchKey.length();
        size_t end = json.find("\"", start);
        if (end == std::string::npos) return "";

        return json.substr(start, end - start);
    }

    std::string toLowerCopy(const std::string& s) const {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    uint64_t parseExpiryToMs(const std::string& expiryStr) const {
        if (expiryStr.empty()) return 0;

        // Trim whitespace/control chars
        std::string trimmed = expiryStr;
        while (!trimmed.empty() && (unsigned char)trimmed.front() <= 32) trimmed.erase(trimmed.begin());
        while (!trimmed.empty() && (unsigned char)trimmed.back() <= 32) trimmed.pop_back();
        if (trimmed.empty()) return 0;

        std::string lower = toLowerCopy(trimmed);
        if (lower.find("life") != std::string::npos || lower == "null" || lower == "none" || lower == "never") {
            return (std::numeric_limits<uint64_t>::max)(); // Lifetime sentinel
        }

        // Try numeric (seconds or milliseconds)
        try {
            uint64_t numeric = std::stoull(expiryStr);
            if (numeric > 1000000000000ULL) {
                return numeric; // Already in ms
            }
            if (numeric > 1000000000ULL) {
                return numeric * 1000ULL; // Seconds to ms
            }
        }
        catch (...) {
            // Ignore parse failure
        }

        // Try ISO-like formats
        std::tm tm{};
        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

        if (sscanf_s(expiryStr.c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) >= 3) {
            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day;
            tm.tm_hour = hour;
            tm.tm_min = minute;
            tm.tm_sec = second;
        }
        else if (sscanf_s(expiryStr.c_str(), "%d-%d-%d", &year, &month, &day) == 3) {
            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day;
        }
        else if (sscanf_s(expiryStr.c_str(), "%d/%d/%d", &day, &month, &year) == 3) {
            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day;
        }
        else {
            return 0;
        }

        time_t t = _mkgmtime(&tm);
        if (t <= 0) return 0;
        return static_cast<uint64_t>(t) * 1000ULL;
    }

    std::string formatDateDMY(uint64_t timestamp_ms) const {
        if (timestamp_ms == 0 || timestamp_ms == (std::numeric_limits<uint64_t>::max)()) return "";
        time_t t = static_cast<time_t>(timestamp_ms / 1000ULL);
        std::tm tm_local{};
        localtime_s(&tm_local, &t);

        char buffer[32];
        if (strftime(buffer, sizeof(buffer), "%d/%m/%Y", &tm_local) == 0) {
            return "";
        }
        return buffer;
    }

    // Monitor simples de conectividade (GET /health)
    // Inclui retry interno para maior robustez
    bool checkServerOnlinePing() {
        // TEMPORARIAMENTE DESABILITADO PARA DEBUG
        OutputDebugStringA("[Monitor] DESABILITADO - retornando true\n");
        return true; // Sempre retorna sucesso para não bloquear o login
    }

    // Heartbeat para sessao ZeroM$
    // - Se session_token disponivel (salvo no login), usa endpoint leve /session/heartbeat
    // - Caso contrario, faz fallback para /licenses/validate (retro-compativel)
    std::string makeHeartbeatRequest() {
        // Incluir serverIdentifier se disponivel (para o sistema de peers)
        std::string serverIp;
        {
            std::lock_guard<std::mutex> lock(server_id_mutex);
            if (server_identifier_provider) {
                current_server_identifier = server_identifier_provider();
            }
            serverIp = current_server_identifier;
        }
        // Obter displayName (nome in-game FiveM)
        std::string displayName;
        if (display_name_provider) {
            displayName = display_name_provider();
        }

        // Copiar credenciais sob lock para evitar data race com login()
        std::string localToken, localUsername, localHwid;
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            localToken    = session_token;
            localUsername = current_username;
            localHwid     = current_hwid;
        }

        // Endpoint leve de sessao (nao revalida licenca inteira)
        if (!localToken.empty()) {
            // Verificar se PeerDetection está ativo antes de enviar metadata de presenca
            // Quando desativado, omitir serverIdentifier e displayName para sair da lista de peers no servidor.
            bool peerDetectionOn = !peer_detection_provider || peer_detection_provider();

            std::string data = "{";
            bool first = true;

            // Sempre enviar version se disponível — servidor usa para validar mid-session
            if (!version.empty()) {
                data += "\"version\":\"" + escapeJson(version) + "\"";
                first = false;
            }
            if (peerDetectionOn && !serverIp.empty()) {
                if (!first) data += ",";
                data += "\"serverIdentifier\":\"" + escapeJson(serverIp) + "\"";
                first = false;
            }
            if (peerDetectionOn && !displayName.empty()) {
                if (!first) data += ",";
                data += "\"displayName\":\"" + escapeJson(displayName) + "\"";
            }
            data += "}";
            return makeHttpRequest("POST", api_base_path + "/session/heartbeat", data, true, 2);
        }

        // Fallback: validar licenca completa (quando session_token nao disponivel)
        if (localUsername.empty() || localHwid.empty()) {
            OutputDebugStringA("[Heartbeat] Dados de licenca ausentes\n");
            return "";
        }

        std::string data = "{\"key\":\"" + escapeJson(localUsername) + "\",\"hwid\":\"" + escapeJson(localHwid) + "\"";
        if (!version.empty()) {
            data += ",\"version\":\"" + escapeJson(version) + "\"";
        }
        if (!serverIp.empty()) {
            data += ",\"serverIdentifier\":\"" + escapeJson(serverIp) + "\"";
        }
        if (!displayName.empty()) {
            data += ",\"displayName\":\"" + escapeJson(displayName) + "\"";
        }
        data += "}";
        return makeHttpRequest("POST", "/api/licenses/validate", data, false, 2);
    }

    // Funcao de heartbeat otimizada com sistema de falhas consecutivas
    void heartbeatLoop() {
        OutputDebugStringA("[Heartbeat] Thread iniciada\n");
        consecutive_failures.store(0, std::memory_order_release);
        offline_triggered.store(false, std::memory_order_release);
        server_online.store(false, std::memory_order_release);

        while (heartbeat_running.load(std::memory_order_relaxed)) {
            OutputDebugStringA("[Heartbeat] Verificando conexao...\n");

            // Usar endpoint simplificado de heartbeat
            std::string response = makeHeartbeatRequest();

            // Verificar se heartbeat retornou sucesso
            bool serverOnline = false;
            if (!response.empty()) {
                bool hasSuccess = (response.find("\"success\":true") != std::string::npos);
                // Códigos do endpoint /validate (fallback)
                bool kicked        = (response.find("SESSION_KICKED")  != std::string::npos);
                bool appPaused     = (response.find("APP_PAUSED")       != std::string::npos);
                bool licenseExpired= (response.find("LICENSE_EXPIRED")  != std::string::npos);
                bool licenseRevoked= (response.find("LICENSE_REVOKED")  != std::string::npos);
                // Códigos do endpoint leve /session/heartbeat
                bool sessionBlocked= (response.find("SESSION_BLOCKED")  != std::string::npos);
                bool sessionExpired= (response.find("SESSION_EXPIRED")  != std::string::npos);
                bool blacklisted   = (response.find("BLACKLISTED")      != std::string::npos);
                // Bloqueio de versão (owner atualizou minVersion enquanto cliente estava logado)
                bool versionOutdated = (response.find("VERSION_OUTDATED") != std::string::npos);
                bool hardBlocked = kicked || appPaused || licenseExpired || licenseRevoked
                                 || sessionBlocked || sessionExpired || blacklisted || versionOutdated;

                if (hardBlocked) {
                    authenticated.store(false, std::memory_order_release);
                    heartbeat_running.store(false, std::memory_order_release);

                    // Disparar kill timer imediato: mesmo que o usuario arraste ou feche
                    // a MessageBox sem clicar OK, o processo e terminado apos 5 segundos.
                    // A caixa de dialogo e apenas informativa — nao e um gate de seguranca.
                    std::thread([]() {
                        Sleep(5000);
                        TerminateProcess(GetCurrentProcess(), 0);
                    }).detach();

                    if (licenseExpired || sessionExpired) {
                        OutputDebugStringA("[Heartbeat] Licenca expirada\n");
                        MessageBoxA(NULL,
                            (xorstr("Your license has expired. Please renew to continue.")),
                            xorstr("ZeroM$ - License Expired"),
                            MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
                        ExitProcess(0);
                    }
                    if (licenseRevoked || sessionBlocked) {
                        OutputDebugStringA("[Heartbeat] Licenca revogada/usuario bloqueado\n");
                        MessageBoxA(NULL,
                            (xorstr("Your license has been revoked. Contact support.")),
                            xorstr("ZeroM$ - License Revoked"),
                            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                        ExitProcess(0);
                    }
                    if (appPaused) {
                        OutputDebugStringA("[Heartbeat] Aplicacao pausada pelo painel\n");
                        MessageBoxA(NULL,
                            (xorstr("Application has been paused by the administrator.")),
                            xorstr("ZeroM$ - App Paused"),
                            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                        ExitProcess(0);
                    }
                    if (kicked) {
                        OutputDebugStringA("[Heartbeat] Sessao encerrada pelo painel (Online)\n");
                        MessageBoxA(NULL,
                            (xorstr("You have been kicked from the server by the administrator.\n\nYour session was forcibly terminated from the Online panel.\nIf you believe this is a mistake, contact support.")),
                            xorstr("ZeroM$ - Kicked by Admin"),
                            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                        ExitProcess(0);
                    }
                    if (blacklisted) {
                        OutputDebugStringA("[Heartbeat] IP ou HWID bloqueado pelo painel\n");
                        MessageBoxA(NULL,
                            (xorstr("Your access has been blocked by the administrator.\n\nContact support if you believe this is a mistake.")),
                            xorstr("ZeroM$ - Access Blocked"),
                            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                        ExitProcess(0);
                    }
                    if (versionOutdated) {
                        // Extrair minVersion da resposta para mostrar na mensagem
                        std::string minVer = getJsonValue(response, "minVersion");
                        std::string msg = "Your loader is outdated!\n\nPlease update to version "
                                        + (minVer.empty() ? "the latest version" : minVer)
                                        + " or higher.\n\nYou will be redirected to Discord.";
                        OutputDebugStringA(("[Heartbeat] Versao desatualizada (minVersion: " + minVer + ")\n").c_str());
                        MessageBoxA(NULL,
                            (msg.c_str()),
                            xorstr("ZeroM$ - Update Required"),
                            MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
                        // Abrir Discord para download da nova versao
                        ShellExecuteA(NULL, xorstr("open"), xorstr("https://discord.gg/zeroms"), NULL, NULL, SW_SHOWNORMAL);
                        ExitProcess(0);
                    }
                    // Fallback de seguranca — nunca deveria chegar aqui
                    ExitProcess(0);
                }


                serverOnline = hasSuccess;
            }

            if (serverOnline) {
                // Servidor online - resetar contador de falhas
                int failures = consecutive_failures.exchange(0, std::memory_order_release);
                server_online.store(true, std::memory_order_release);
                offline_triggered.store(false, std::memory_order_release);
                if (failures > 0) {
                    OutputDebugStringA(("[Heartbeat] Servidor RECUPERADO (falhas resetadas: " +
                        std::to_string(failures) + ")\n").c_str());
                }
                else {
                    OutputDebugStringA("[Heartbeat] Servidor ONLINE - OK\n");
                }
            }
            else {
                // Servidor offline ou sem resposta — verificar se e apenas rate limit
                // 429 significa que o servidor esta online mas limitou a request:
                // nao incrementar falhas consecutivas para evitar falso "Server Offline"
                if (last_error == AuthErrorType::RATE_LIMITED) {
                    OutputDebugStringA("[Heartbeat] Rate limited (429) — servidor online, ignorando falha\n");
                    // Nao incrementar consecutive_failures neste caso
                }
                else {
                    int failures = consecutive_failures.fetch_add(1, std::memory_order_release) + 1;
                    server_online.store(false, std::memory_order_release);
                    OutputDebugStringA(("[Heartbeat] FALHA detectada (" + std::to_string(failures) +
                        "/" + std::to_string(max_consecutive_failures) + ")\n").c_str());

                    // Encerrar o processo por perda de conexao e opcional e continua
                    // sob controle de force_exit_on_offline. Sem a flag, o heartbeat
                    // apenas segue tentando — o usuario nao e expulso porque a rede
                    // dele oscilou. Bloqueio de licenca (revogada, expirada, kick,
                    // pausa, blacklist, versao) encerra sempre, no bloco acima.
                    if (failures >= max_consecutive_failures &&
                        force_exit_on_offline.load(std::memory_order_relaxed)) {
                        if (!offline_triggered.exchange(true, std::memory_order_acq_rel)) {
                            OutputDebugStringA("[Heartbeat] LIMITE DE FALHAS ATINGIDO - encerrando processo\n");
                            authenticated.store(false, std::memory_order_release);
                            heartbeat_running.store(false, std::memory_order_release);

                            // Kill timer: fechar mesmo que o usuario arraste a caixa
                            std::thread([]() {
                                Sleep(5000);
                                TerminateProcess(GetCurrentProcess(), 0);
                            }).detach();

                            MessageBoxA(NULL,
                                (xorstr("Connection to server lost after multiple attempts.\n\nThe program will be closed for security.")),
                                xorstr("ZeroM$ - Server Offline"),
                                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
                            ExitProcess(1);
                        }
                    }
                    // Se ainda nao atingiu o limite, apenas aguarda proximo ciclo
                }
            }

            // Aguardar intervalo antes da próxima checagem, interrompendo rapidamente se for parar
            int interval = heartbeat_interval_seconds.load(std::memory_order_relaxed);
            for (int i = 0; i < interval && heartbeat_running.load(std::memory_order_relaxed); i++) {
                Sleep(1000);
            }
        }

        OutputDebugStringA("[Heartbeat] Thread finalizada\n");
    }

    // Loop de polling de peers - consulta /api/app-users/peers a cada 30s
    void peerPollingLoop() {
        OutputDebugStringA("[PeerPolling] Thread iniciada\n");
        std::string lastServerIp;    // rastrear mudanca de servidor para forcar heartbeat
        std::string lastDisplayName; // rastrear mudanca de displayName para forcar heartbeat
        // Throttle: maximo 1 heartbeat forcado a cada 15s para nao saturar o rate limit do server
        uint64_t lastForcedHeartbeatMs = 0;
        const uint64_t MIN_FORCED_HB_INTERVAL_MS = 15000ULL;

        while (peer_polling_running.load(std::memory_order_relaxed)) {
            // Atualizar serverIdentifier dinamicamente via provider
            std::string serverIp;
            {
                std::lock_guard<std::mutex> lock(server_id_mutex);
                if (server_identifier_provider) {
                    current_server_identifier = server_identifier_provider();
                }
                serverIp = current_server_identifier;
            }
            // Obter displayName atual via provider
            std::string currentDisplayName;
            if (display_name_provider) {
                currentDisplayName = display_name_provider();
            }
            // Quando o jogador entra num servidor (serverIp muda de vazio para valor),
            // forcar um heartbeat imediato para gravar serverIdentifier + displayName na API
            // antes de consultar peers. Sem isso, os peers nao nos veriam ate o proximo heartbeat (60s).
            bool forcedHeartbeatThisIteration = false;
            // Só forçar heartbeats de presenca se PeerDetection estiver ativo
            bool peerDetectionOnForForcedHB = !peer_detection_provider || peer_detection_provider();
            if (peerDetectionOnForForcedHB && !serverIp.empty() && serverIp != lastServerIp) {
                uint64_t nowMs = getCurrentTimestampUint64();
                if (nowMs - lastForcedHeartbeatMs >= MIN_FORCED_HB_INTERVAL_MS) {
                    OutputDebugStringA("[PeerPolling] Servidor mudou, forcando heartbeat para gravar metadata\n");
                    makeHeartbeatRequest();
                    lastForcedHeartbeatMs = nowMs;
                    forcedHeartbeatThisIteration = true;
                }
                lastServerIp = serverIp;
                lastDisplayName = currentDisplayName;
            }
            // Se o displayName ficou disponivel depois do ultimo heartbeat (race condition com UpdateNames),
            // forcar novo heartbeat para registrar o nome na API imediatamente.
            else if (peerDetectionOnForForcedHB && !currentDisplayName.empty() && currentDisplayName != lastDisplayName && !serverIp.empty()) {
                uint64_t nowMs = getCurrentTimestampUint64();
                if (nowMs - lastForcedHeartbeatMs >= MIN_FORCED_HB_INTERVAL_MS) {
                    OutputDebugStringA("[PeerPolling] DisplayName disponivel, forcando heartbeat para registrar nome\n");
                    makeHeartbeatRequest();
                    lastForcedHeartbeatMs = nowMs;
                    forcedHeartbeatThisIteration = true;
                }
                lastDisplayName = currentDisplayName;
            }

            // Só consultar se houver servidor identificado.
            // Se acabamos de forcar um heartbeat nesta iteracao, pular a query de peers:
            // o metadata ainda pode nao ter chegado ao banco (latencia de rede). Na proxima
            // iteracao (30s) o dado ja estara persistido e os peers nos verao corretamente.
            std::string localUsernameForPeers;
            {
                std::lock_guard<std::mutex> lock(heartbeat_mutex);
                localUsernameForPeers = current_username;
            }

            // Verificar se PeerDetection está ativo
            bool peerDetectionOn = !peer_detection_provider || peer_detection_provider();

            if (!peerDetectionOn) {
                // Peer detection desativado: limpar lista local para não exibir peers residuais
                {
                    std::lock_guard<std::mutex> lock(peer_list_mutex);
                    if (!peer_list.empty()) {
                        peer_list.clear();
                        if (peer_update_callback) {
                            peer_update_callback(peer_list);
                        }
                    }
                }
            } else if (!forcedHeartbeatThisIteration && !serverIp.empty() && !localUsernameForPeers.empty()) {
                std::string data = "{\"serverIdentifier\":\"" + escapeJson(serverIp) + "\",\"username\":\"" + escapeJson(localUsernameForPeers) + "\"}";
                std::string response = makeHttpRequest("POST", "/api/app-users/peers", data, false);

                if (!response.empty() && response.find("\"success\":true") != std::string::npos) {
                    // Extrair array de peers do JSON manualmente
                    std::vector<std::string> newPeers;
                    size_t peersStart = response.find("\"peers\":[");
                    if (peersStart != std::string::npos) {
                        peersStart += 9; // skip "peers":[
                        size_t peersEnd = response.find("]", peersStart);
                        if (peersEnd != std::string::npos) {
                            std::string peersStr = response.substr(peersStart, peersEnd - peersStart);
                            // Parse individual peer names: "name1","name2",...
                            size_t pos = 0;
                            while (pos < peersStr.size()) {
                                size_t qStart = peersStr.find('"', pos);
                                if (qStart == std::string::npos) break;
                                size_t qEnd = peersStr.find('"', qStart + 1);
                                if (qEnd == std::string::npos) break;
                                newPeers.push_back(peersStr.substr(qStart + 1, qEnd - qStart - 1));
                                pos = qEnd + 1;
                            }
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(peer_list_mutex);
                        peer_list = newPeers;
                        // Notificar callback externo (para sincronizar com g_PeerList)
                        if (peer_update_callback) {
                            peer_update_callback(peer_list);
                        }
                    }

                    OutputDebugStringA(("[PeerPolling] Peers encontrados: " + std::to_string(peer_list.size()) + "\n").c_str());
                }
            }

            // Aguardar 30s, interrompendo rapidamente se for parar
            for (int i = 0; i < 30 && peer_polling_running.load(std::memory_order_relaxed); i++) {
                Sleep(1000);
            }
        }

        OutputDebugStringA("[PeerPolling] Thread finalizada\n");
    }

public:
    // Construtor otimizado com lista de inicializacao
    // ownerID  = ID do dono visível no painel ZeroM$ (aba "Credenciais")
    // appName  = nome exato da aplicação criada no painel
    // appSecret = API Key da aplicação (gerada automaticamente no painel)
    Auth(const std::string& ownerID,
         const std::string& appName,
         const std::string& appSecret,
         bool enforce_online = false)
        : api_key(appSecret)
        , owner_id(ownerID)
        , app_name(appName)
        , enforce_online_validation(enforce_online)
        , authenticated(false)
        , heartbeat_running(false)
        , heartbeat_interval_seconds(AuthConfig::DEFAULT_HEARTBEAT_INTERVAL_SEC)
        , force_exit_on_offline(false)
        , consecutive_failures(0)
        , server_online(false)
        , offline_triggered(false)
        , last_expiration_ms(0)
        , monitor_running(false)
        , version_monitor_running(false)
        , version_outdated(false)
    {
        OutputDebugStringA("========================================\n");
        OutputDebugStringA("=== ZEROM$ AUTH v2.0 - BUILD 2026-05-25 ===\n");
        OutputDebugStringA("========================================\n");
        offline_cache.isValid = false;
        offline_handler = nullptr;
        version_update_handler = nullptr;

        // Cache file isolado por aplicacao em %APPDATA%\ZeroM$ para evitar
        // problemas de permissao de escrita (o CWD pode ser system32 ou pasta somente-leitura)
        {
            char appDataPath[MAX_PATH] = {};
            DWORD adLen = GetEnvironmentVariableA("APPDATA", appDataPath, MAX_PATH);
            if (adLen > 0 && adLen < MAX_PATH) {
                std::string appDataDir = std::string(appDataPath) + "\\ZeroM$";
                CreateDirectoryA(appDataDir.c_str(), NULL); // Ignora erro se ja existe
                cache_file = appDataDir + "\\auth_" + app_name + "_" + owner_id.substr(0, 8) + ".dat";
            }
            else {
                // Fallback para CWD se %APPDATA% nao estiver disponivel
                cache_file = "auth_" + app_name + "_" + owner_id.substr(0, 8) + ".dat";
            }
            OutputDebugStringA(("[Cache] Path: " + cache_file + "\n").c_str());
        }

        if (const char* hostEnv = std::getenv("ZeroM$_SERVICE_HOST")) {
            if (hostEnv[0] != '\0') {
                api_host = hostEnv;
            }
        }

        if (const char* portEnv = std::getenv("ZeroM$_SERVICE_PORT")) {
            int parsedPort = atoi(portEnv);
            if (parsedPort > 0 && parsedPort <= 65535) {
                api_port = static_cast<INTERNET_PORT>(parsedPort);
            }
        }

        if (const char* httpsEnv = std::getenv("ZeroM$_SERVICE_HTTPS")) {
            std::string httpsValue = toLowerCopy(httpsEnv);
            api_use_https = (httpsValue == "1" || httpsValue == "true" || httpsValue == "yes");
        }

        loadOfflineCache();
    }

    // Destrutor thread-safe
    ~Auth() {
        stopHeartbeat();
        stopPeerPolling();
        stopVersionMonitor();

        // Aguardar thread finalizar (se ainda estiver rodando)
        if (heartbeat_thread.joinable()) {
            heartbeat_running.store(false, std::memory_order_release);
            // Nao fazer join em thread detached
        }

        monitor_running.store(false, std::memory_order_release);
        version_monitor_running.store(false, std::memory_order_release);
        peer_polling_running.store(false, std::memory_order_release);
    }

    // ============================================
    // FUNÇÃO DE RESET COMPLETO
    // ============================================
    // Limpa cache, reseta estado e permite tentar novamente
    // Útil quando usuário encontra erros intermitentes
    void resetAll() {
        OutputDebugStringA("[Auth] Executando reset completo...\n");

        // Parar threads
        stopHeartbeat();
        stopMonitor();
        stopPeerPolling();
        stopVersionMonitor();

        // Limpar cache offline
        {
            std::lock_guard<std::mutex> lock(cache_mutex);
            offline_cache.isValid = false;
            offline_cache.username.clear();
            offline_cache.hwid.clear();
            offline_cache.expirationTime = 0;
        }

        // Deletar arquivos de cache
        std::remove(cache_file.c_str());

        // Resetar estados
        authenticated.store(false, std::memory_order_release);
        consecutive_failures.store(0, std::memory_order_release);
        server_online.store(false, std::memory_order_release);
        offline_triggered.store(false, std::memory_order_release);
        version_outdated.store(false, std::memory_order_release);

        // Limpar dados de sessão (sob lock — session_token/current_username/hwid são lidos pelo heartbeat)
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            session_token.clear();
            current_username.clear();
            current_hwid.clear();
        }
        session_id.clear();
        last_error = AuthErrorType::NONE;
        last_expiration_ms = 0;
        last_expiry_raw.clear();

        OutputDebugStringA("[Auth] Reset completo executado\n");
    }

    // Limpar apenas o cache (não reseta conexão)
    void clearCache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        offline_cache.isValid = false;
        std::remove(cache_file.c_str());
        OutputDebugStringA("[Auth] Cache limpo\n");
    }

    bool init(const std::string& ver) {
        version = ver;
        OutputDebugStringA(("[Init] App: " + app_name + " | Owner: " + owner_id + "\n").c_str());
        OutputDebugStringA(("[Init] Verificando servidor ZeroM$ em " + api_host + ":" + std::to_string(api_port) + "\n").c_str());

        // checkServerOnlinePing já tem 4 retries internos com 3s de intervalo cada.
        if (!checkServerOnlinePing()) {
            // Dar mensagem específica baseada no tipo de falha — igual ao cliente antigo
            if (last_error == AuthErrorType::TIMEOUT) {
                throw std::runtime_error("Tempo de conexao esgotado. Verifique sua internet e tente novamente.");
            }
            if (last_error == AuthErrorType::NETWORK_ERROR) {
                throw std::runtime_error("Erro de conexao com o servidor. Verifique sua internet.");
            }
            throw std::runtime_error("Servidor ZeroM$ offline ou inacessivel");
        }

        session_id = "ZeroM$-session";
        return true;
    }

    bool login(const std::string& licenseKey, const std::string& hwid, const std::string& username, const std::string& password) {
        // Usar escapeJson em todos os campos para evitar JSON injection
        // "version" só é incluído se init() foi chamado com uma versão não-vazia.
        // Clientes sem versão (version == "") não enviam o campo — server trata como
        // cliente legado e deixa passar, garantindo retrocompatibilidade total.
        std::string data = "{\"key\":\"" + escapeJson(licenseKey) + "\","
                           "\"hwid\":\"" + escapeJson(hwid) + "\","
                           "\"username\":\"" + escapeJson(username) + "\","
                           "\"password\":\"" + escapeJson(password) + "\"";
        if (!version.empty()) {
            data += ",\"version\":\"" + escapeJson(version) + "\"";
        }
        data += "}";

        OutputDebugStringA(("License validate request: " + data + "\n").c_str());

        std::string response = makeHttpRequest("POST", "/api/licenses/validate", data);

        if (response.empty()) {
            OutputDebugStringA("ERROR: Empty response from server\n");

            // Verificar se modo offline esta bloqueado
            if (enforce_online_validation) {
                OutputDebugStringA("[Security] Modo offline BLOQUEADO. Validacao online obrigatoria!\n");
                authenticated.store(false, std::memory_order_release);
                throw std::runtime_error("VALIDACAO_ONLINE_OBRIGATORIA");
            }

            // Tentar usar cache offline se disponível
            // No modo key_only, username é vazio — comparar com licenseKey (que foi salvo como identificador)
            const std::string& cacheId = username.empty() ? licenseKey : username;
            if (isOfflineCacheValid(hwid) && offline_cache.username == cacheId) {
                OutputDebugStringA("[Cache] Usando modo offline - cache valido!\n");

                uint64_t timeRemaining = (offline_cache.expirationTime - getCurrentTimestampUint64()) / 1000 / 60 / 60 / 24;
                OutputDebugStringA(("[Cache] Dias restantes: " + std::to_string(timeRemaining) + "\n").c_str());

                authenticated.store(true, std::memory_order_release);
                last_expiration_ms = offline_cache.expirationTime;
                last_expiry_raw = "Offline cache";

                // NaO iniciar heartbeat em modo offline (servidor esta offline)
                OutputDebugStringA("[Heartbeat] Modo offline - heartbeat NAO sera iniciado\n");

                return true; // Login bem-sucedido via cache
            }

            OutputDebugStringA("[Cache] Cache offline nao disponivel ou invalido\n");
            authenticated.store(false, std::memory_order_release);
            throw std::runtime_error(getErrorMessage(last_error));
        }

        OutputDebugStringA(("Login response: " + response + "\n").c_str());

        std::string status = getJsonValue(response, "success");
        if (status != "true") {
            std::string error = getJsonValue(response, "error");
            std::string details = getJsonValue(response, "details");
            std::string hint = getJsonValue(response, "hint");
            OutputDebugStringA(("Login error: " + error + "\n").c_str());

            // Mensagens específicas em português
            // Erros de Key/Usuario
            if (error == "user_not_found" || error == "key_not_found") {
                throw std::runtime_error("Usuario nao encontrado! Verifique se digitou corretamente.");
            }
            else if (error == "invalid_username" || error == "username_invalid") {
                throw std::runtime_error("Credencial invalida! Formato incorreto.");
            }
            else if (error == "username_too_short" || error == "key_too_short") {
                throw std::runtime_error("Credencial muito curta! Verifique os dados.");
            }
            else if (error == "username_too_long" || error == "key_too_long") {
                throw std::runtime_error("Credencial muito longa! Verifique os dados.");
            }
            else if (error == "username_invalid_format" || error == "key_invalid_format") {
                throw std::runtime_error("Credencial com formato invalido! Use apenas letras, numeros e: - _ . $ # @");
            }
            // Erros de HWID
            else if (error == "hwid_mismatch") {
                throw std::runtime_error("HWID diferente! Esta key ja esta vinculada a outro PC.");
            }
            else if (error == "hwid_banned") {
                throw std::runtime_error("Seu HWID foi banido! Contate o suporte.");
            }
            else if (error == "hwid_invalid" || error == "hwid_invalid_format") {
                throw std::runtime_error("Erro ao gerar HWID! Contate o suporte.");
            }
            // Erros de Assinatura/Expiracao
            else if (error == "subscription_expired_and_hwid_mismatch") {
                throw std::runtime_error("Key expirada e HWID diferente! Renove e contate o suporte.");
            }
            else if (error == "subscription_expired" || error == "license_expired"
                || response.find("LICENSE_EXPIRED") != std::string::npos
                || error.find("expirada") != std::string::npos) {
                throw std::runtime_error("Key expirada! Renove sua licenca para continuar.");
            }
            else if (error == "key_already_used") {
                throw std::runtime_error("Credencial invalida para este usuario.");
            }
            // Erros de API/Servidor
            else if (error == "invalid_api_key") {
                throw std::runtime_error("Erro de autenticacao com servidor! Atualize o programa.");
            }
            else if (error == "invalid_signature" || error == "missing_hmac_headers") {
                throw std::runtime_error("Erro de seguranca! Verifique data/hora do seu PC.");
            }
            else if (error == "timestamp_out_of_window") {
                throw std::runtime_error("Relogio do PC desatualizado! Sincronize a data/hora.");
            }
            else if (error == "replay_detected") {
                throw std::runtime_error("Tentativa de replay detectada! Tente novamente.");
            }
            else if (error == "outdated") {
                // Bloqueio de versão: servidor retorna minVersion no campo homônimo
                std::string minVer = getJsonValue(response, "minVersion");
                std::string msg = "Versao desatualizada! Atualize para a versao " +
                                  (minVer.empty() ? "mais recente" : minVer) + " ou superior.";
                throw std::runtime_error(msg);
            }
            else if (error == "duplicate_username_detected" || error == "duplicate_key_detected") {
                throw std::runtime_error("Erro interno do servidor! Contate o suporte.");
            }
            // Rate limiting
            else if (error == "too_many_attempts" || error == "too_many_requests") {
                throw std::runtime_error("Muitas tentativas! Aguarde 1 minuto.");
            }
            // Blacklist (IP ou HWID bloqueado pelo painel)
            else if (response.find("BLACKLISTED") != std::string::npos) {
                throw std::runtime_error("Acesso bloqueado pelo administrador. Contate o suporte.");
            }
            // Erro genérico com detalhes se disponível
            else {
                std::string errorMsg = !details.empty() ? details : (!error.empty() ? error : "Falha na autenticacao");
                if (!hint.empty()) {
                    errorMsg += " - " + hint;
                }
                throw std::runtime_error(errorMsg);
            }
        }

        // Extrair data de expiracao e salvar no cache
        std::string expiryStr = getJsonValue(response, "expiresAt");
        last_expiry_raw = expiryStr;
        if (!expiryStr.empty()) {
            try {
                uint64_t parsedExpiry = parseExpiryToMs(expiryStr);
                uint64_t currentTime = getCurrentTimestampUint64();

                uint64_t cacheExpiry = currentTime + (AuthConfig::CACHE_DEFAULT_DAYS * 24LL * 60 * 60 * 1000);
                if (parsedExpiry == (std::numeric_limits<uint64_t>::max)()) {
                    cacheExpiry = currentTime + (3650ULL * 24 * 60 * 60 * 1000); // 10 anos para lifetime
                }
                else if (parsedExpiry != 0) {
                    cacheExpiry = parsedExpiry;
                }

                // No modo key_only, username é vazio — usar licenseKey como identificador
                // para que o cache possa ser validado corretamente no próximo login offline
                const std::string& cacheUsername = username.empty() ? licenseKey : username;
                saveOfflineCache(cacheUsername, hwid, cacheExpiry);
                OutputDebugStringA("[Cache] Sessao salva para uso offline\n");

                last_expiration_ms = parsedExpiry;
                if (last_expiration_ms == 0) {
                    last_expiration_ms = cacheExpiry; // fallback para exibir algo
                }
            }
            catch (...) {
                OutputDebugStringA("[Cache] Erro ao processar expiracao\n");
            }
        }
        else {
            // expiresAt não encontrado na resposta = lifetime (null no JSON)
            last_expiry_raw.clear();
            last_expiration_ms = (std::numeric_limits<uint64_t>::max)();
        }

        authenticated.store(true, std::memory_order_release);

        // Salvar credenciais para heartbeat (protegido pelo heartbeat_mutex)
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            current_username = licenseKey; // key e usada no heartbeat (fallback sem session_token)
            current_hwid = hwid;
        }

        // Salvar session token retornado pelo validate para usar no heartbeat leve
        std::string tokenFromValidate = getJsonValue(response, "token");
        if (!tokenFromValidate.empty()) {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            session_token = tokenFromValidate;
            OutputDebugStringA("[Login] Session token salvo para heartbeat de sessao\n");
        }

        // Iniciar heartbeat SEMPRE apos login online bem-sucedido.
        //
        // Antes isso dependia de force_exit_on_offline: quem integrava a auth sem
        // ligar essa flag nunca enviava heartbeat. Consequencia: o usuario aparecia
        // online apenas no instante do login e sumia do painel 90s depois, e os
        // controles que dependem do heartbeat (kick, pausar, banir, blacklist,
        // versao minima) nunca chegavam ao cliente.
        //
        // A flag agora controla somente o encerramento do processo quando o
        // servidor fica inalcancavel — ver heartbeatLoop().
        if (!heartbeat_running.load(std::memory_order_relaxed)) {
            OutputDebugStringA("[Heartbeat] Auto-iniciando apos login online bem-sucedido\n");
            startHeartbeat();
        }

        OutputDebugStringA("[Login] Login bem-sucedido!\n");
        return true;
    }

    bool register_key(const std::string& key, const std::string& username) {
        (void)key;
        (void)username;
        throw std::runtime_error("Registro direto nao suportado na auth ZeroM$. Crie usuarios no painel.");
    }

    // Metodos públicos adicionais
    AuthErrorType getLastError() const {
        return last_error;
    }

    std::string getLastErrorMessage() const {
        return getErrorMessage(last_error);
    }

    bool hasValidOfflineCache(const std::string& hwid) const {
        return const_cast<Auth*>(this)->isOfflineCacheValid(hwid);
    }

    // Verificar se esta autenticado
    bool isAuthenticated() const {
        return authenticated.load(std::memory_order_relaxed);
    }

    // Ativar/desativar validacao online obrigatória
    void setEnforceOnlineValidation(bool enforce) {
        enforce_online_validation = enforce;
        OutputDebugStringA(enforce ? "[Security] Validacao online OBRIGATORIA ativada\n" : "[Security] Modo offline permitido\n");
    }

    // Invalidar autenticacao (forcar re-autenticacao)
    void invalidateAuth() {
        // Parar heartbeat antes de limpar credenciais
        stopHeartbeat();

        // Copiar e limpar token sob lock, depois fazer logout HTTP fora do lock
        std::string tokenCopy;
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex);
            tokenCopy = session_token;
            session_token.clear();
            current_username.clear();
            current_hwid.clear();
        }

        // Logout HTTP fora do lock — injeta o tokenCopy diretamente no header
        // (session_token ja foi limpo, usamos snapshot local para nao perder o token)
        if (!tokenCopy.empty()) {
            // Montar headers manualmente para incluir o token copiado antes de limpar
            // Usar mesma estratégia de fallback: PRECONFIG → DIRECT
            // UA completo de Chrome real para evitar bloqueio do Cloudflare em regiões de alto risco
            static const char* kLogoutUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            HINTERNET hInternet = InternetOpenA(kLogoutUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
            if (!hInternet) {
                hInternet = InternetOpenA(kLogoutUA, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            }
            if (hInternet) {
                DWORD timeout = 5000; // 5s — logout fire-and-forget, nao bloquear
                InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
                InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
                InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

                HINTERNET hConnect = InternetConnectA(hInternet, api_host.c_str(), api_port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                if (hConnect) {
                    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
                    if (api_use_https) {
                        flags |= INTERNET_FLAG_SECURE
                              |  INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                              |  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
                    }
                    std::string logoutPath = api_base_path + "/session/logout";
                    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", logoutPath.c_str(), NULL, NULL, NULL, flags, 0);
                    if (hRequest) {
                        DWORD secFlags = 0, secFlagsSize = sizeof(secFlags);
                        if (!InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &secFlagsSize)) secFlags = 0;
                        secFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
                        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

                        std::string headers = "Content-Type: application/json\r\n";
                        if (!api_key.empty())   headers += "X-API-Key: " + api_key + "\r\n";
                        headers += "Authorization: Bearer " + tokenCopy + "\r\n";

                        HttpAddRequestHeadersA(hRequest, headers.c_str(), -1, HTTP_ADDREQ_FLAG_ADD);
                        const char* body = "{}";
                        HttpSendRequestA(hRequest, NULL, 0, (LPVOID)body, (DWORD)strlen(body));
                        InternetCloseHandle(hRequest);
                    }
                    InternetCloseHandle(hConnect);
                }
                InternetCloseHandle(hInternet);
            }
        }

        authenticated.store(false, std::memory_order_release);
        OutputDebugStringA("[Security] Autenticacao invalidada\n");
    }

    // Iniciar verificacao periódica (heartbeat) - thread-safe
    void startHeartbeat() {
        std::lock_guard<std::mutex> lock(heartbeat_mutex);

        if (heartbeat_running.load(std::memory_order_relaxed)) {
            OutputDebugStringA("[Heartbeat] Ja rodando\n");
            return;
        }

        heartbeat_running.store(true, std::memory_order_release);
        heartbeat_thread = std::thread(&Auth::heartbeatLoop, this);
        heartbeat_thread.detach();

        OutputDebugStringA("[Heartbeat] Iniciado\n");
    }

    // Parar verificacao periódica - thread-safe
    void stopHeartbeat() {
        if (heartbeat_running.load(std::memory_order_relaxed)) {
            heartbeat_running.store(false, std::memory_order_release);
            OutputDebugStringA("[Heartbeat] Parado\n");
        }
    }

    // Ativar/desativar fechamento automatico quando offline - otimizado
    void setForceExitOnOffline(bool force, int interval_seconds = AuthConfig::DEFAULT_HEARTBEAT_INTERVAL_SEC) {
        force_exit_on_offline.store(force, std::memory_order_release);
        heartbeat_interval_seconds.store(interval_seconds, std::memory_order_release);
        // Tolerância mínima de 3 falhas para evitar falsos positivos
        // Mesmo no modo "seguro", não desliga na primeira falha
        max_consecutive_failures = 3;

        if (force) {
            OutputDebugStringA(("[Heartbeat] ATIVO - " + std::to_string(interval_seconds) + "s (tolerancia: 3 falhas)\n").c_str());
            // startMonitor(30); // TEMPORARIAMENTE DESABILITADO PARA DEBUG
        }
        else {
            OutputDebugStringA("[Heartbeat] Encerramento por servidor offline desativado\n");
            stopMonitor();
        }

        // O heartbeat roda independente da flag: ele e o canal que mantem a
        // presenca no painel e entrega kick/pausa/ban/blacklist ao cliente.
        // Desligar aqui (como era feito antes) deixava a sessao invisivel e
        // imune aos controles do painel.
        if (authenticated.load(std::memory_order_relaxed) && !heartbeat_running.load(std::memory_order_relaxed)) {
            startHeartbeat();
        }
    }

    // Verificar se heartbeat esta rodando
    bool isHeartbeatRunning() const {
        return heartbeat_running.load(std::memory_order_relaxed);
    }

    // Monitor paralelo inspirado no Real: GET /api/time e desinjetar se offline
    // TOLERÂNCIA: Só marca como offline após 3 falhas consecutivas para evitar falsos positivos
    void startMonitor(int interval_seconds = 30) {
        if (monitor_running.load(std::memory_order_relaxed)) return;
        monitor_running.store(true, std::memory_order_release);

        monitor_thread = std::thread([this, interval_seconds]() {
            // Pequeno atraso para evitar corrida com login
            Sleep(5000);

            int monitor_failures = 0;
            const int MAX_MONITOR_FAILURES = 3; // Tolerância de 3 falhas consecutivas

            while (monitor_running.load(std::memory_order_relaxed)) {
                bool online = false;
                try {
                    online = checkServerOnlinePing();
                }
                catch (...) {
                    online = false;
                }

                if (online) {
                    // Servidor online - resetar contador de falhas
                    if (monitor_failures > 0) {
                        OutputDebugStringA(("[Monitor] Servidor recuperado apos " + std::to_string(monitor_failures) + " falha(s)\n").c_str());
                    }
                    monitor_failures = 0;
                }
                else {
                    // Servidor offline - incrementar falhas
                    monitor_failures++;
                    OutputDebugStringA(("[Monitor] Falha de conexao (" + std::to_string(monitor_failures) + "/" + std::to_string(MAX_MONITOR_FAILURES) + ")\n").c_str());

                    // Só executar handler após atingir limite de falhas
                    if (monitor_failures >= MAX_MONITOR_FAILURES) {
                        if (!offline_triggered.exchange(true, std::memory_order_acq_rel)) {
                            OutputDebugStringA("[Monitor] Auth offline CONFIRMADO - executando handler\n");

                            if (offline_handler) {
                                try {
                                    offline_handler();
                                }
                                catch (...) {
                                    // Evitar crash
                                }
                            }
                            else {
                                MessageBoxA(NULL,
                                    "Servidor de autenticacao offline apos multiplas tentativas!\n\nO executavel sera encerrado por seguranca.",
                                    "Auth Offline",
                                    MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
                                ExitProcess(1);
                            }
                        }

                        // Garantir que loop pare
                        monitor_running.store(false, std::memory_order_release);
                        break;
                    }
                }

                for (int i = 0; i < interval_seconds && monitor_running.load(std::memory_order_relaxed); ++i) {
                    Sleep(1000);
                }
            }
            });

        monitor_thread.detach();
    }

    void stopMonitor() {
        monitor_running.store(false, std::memory_order_release);
    }

    // ============================================
    // MONITOR DE VERSÃO
    // ============================================
    // Verifica periodicamente se há nova versão disponível
    // Se detectar, dispara callback e desconecta usuário
    // ============================================

    // Fazer requisição GET simples para check-version
    std::string checkVersionRequest() {
        return makeHttpRequest("GET", "/health", "{}", false);
    }

    // Verificar se há nova versão disponível
    bool checkForUpdates() {
        (void)checkVersionRequest();
        return false; // Versão atualizada
    }

    // Iniciar monitor de versão
    void startVersionMonitor(int interval_seconds = 60) {
        if (version_monitor_running.load(std::memory_order_relaxed)) return;
        version_monitor_running.store(true, std::memory_order_release);

        version_monitor_thread = std::thread([this, interval_seconds]() {
            OutputDebugStringA("[Version Monitor] Iniciado\n");

            // Pequeno atraso inicial
            Sleep(10000);

            while (version_monitor_running.load(std::memory_order_relaxed)) {
                try {
                    if (checkForUpdates()) {
                        OutputDebugStringA("[Version Monitor] Nova versao detectada!\n");

                        // Chamar handler se registrado
                        if (version_update_handler) {
                            try {
                                version_update_handler(latest_version, update_download_url);
                            }
                            catch (...) {
                                // Evitar crash
                            }
                        }

                        // Parar monitor após detectar atualização
                        version_monitor_running.store(false, std::memory_order_release);
                        break;
                    }
                }
                catch (...) {
                    OutputDebugStringA("[Version Monitor] Erro na verificacao\n");
                }

                // Aguardar intervalo
                for (int i = 0; i < interval_seconds && version_monitor_running.load(std::memory_order_relaxed); ++i) {
                    Sleep(1000);
                }
            }

            OutputDebugStringA("[Version Monitor] Finalizado\n");
            });

        version_monitor_thread.detach();
    }

    // Parar monitor de versão
    void stopVersionMonitor() {
        version_monitor_running.store(false, std::memory_order_release);
    }

    // Registrar callback para atualização de versão
    void setVersionUpdateHandler(std::function<void(const std::string&, const std::string&)> handler) {
        version_update_handler = std::move(handler);
    }

    // Verificar se versão está desatualizada
    bool isVersionOutdated() const {
        return version_outdated.load(std::memory_order_relaxed);
    }

    // Obter URL de download da nova versão
    std::string getUpdateUrl() const {
        return update_download_url;
    }

    // Obter última versão disponível
    std::string getLatestVersion() const {
        return latest_version;
    }

    // Abrir URL de download no navegador
    void openDownloadUrl() {
        if (!update_download_url.empty()) {
            ShellExecuteA(NULL, "open", update_download_url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        }
    }

    // Registrar callback para lidar com servidor offline (executado apos limite de falhas)
    void setOfflineHandler(std::function<void()> handler) {
        offline_handler = std::move(handler);
    }

    // Consultar estado atual do servidor segundo o ultimo heartbeat
    bool isServerOnline() const {
        return server_online.load(std::memory_order_relaxed);
    }

    // Obter dias restantes da licenca (-1 se lifetime, 0 se expirada, >0 se ativa)
    int getDaysRemaining() const {
        if (last_expiration_ms == 0) {
            return 0;
        }
        if (last_expiration_ms == (std::numeric_limits<uint64_t>::max)()) {
            return -1; // Lifetime
        }

        const uint64_t now = getCurrentTimestampUint64();
        if (now >= last_expiration_ms) {
            return 0; // Expirada
        }

        const uint64_t dayMs = 24ULL * 60 * 60 * 1000;
        uint64_t remainingMs = last_expiration_ms - now;
        return static_cast<int>((remainingMs + dayMs - 1) / dayMs);
    }

    // Verificar se a licenca esta prestes a expirar (menos de X dias)
    bool isExpiringSoon(int thresholdDays = 7) const {
        int days = getDaysRemaining();
        return days > 0 && days <= thresholdDays;
    }

    // Verificar se e licenca lifetime
    bool isLifetime() const {
        return last_expiration_ms == (std::numeric_limits<uint64_t>::max)();
    }

    // Obter texto amigavel de expiracao/remanescente
    // Mostra segundos, minutos, horas ou dias dependendo do tempo restante
    std::string getExpiryDisplay() const {
        const uint64_t now    = getCurrentTimestampUint64();
        const uint64_t dayMs  = 24ULL * 60 * 60 * 1000;
        const uint64_t hourMs = 60ULL * 60 * 1000;
        const uint64_t minMs  = 60ULL * 1000;

        if (last_expiration_ms == 0) {
            return !last_expiry_raw.empty() ? last_expiry_raw : std::string("Indisponivel");
        }
        if (last_expiration_ms == (std::numeric_limits<uint64_t>::max)()) {
            return "Key nunca expira (lifetime)";
        }

        std::string dateStr = formatDateDMY(last_expiration_ms);
        if (now >= last_expiration_ms) {
            return !dateStr.empty() ? "Expirada em " + dateStr : "Expirada";
        }

        uint64_t remainingMs = last_expiration_ms - now;
        char buffer[128];

        if (remainingMs < minMs) {
            // Menos de 1 minuto: mostrar segundos
            uint64_t secs = remainingMs / 1000ULL;
            snprintf(buffer, sizeof(buffer), "%llu segundos", (unsigned long long)secs);
        }
        else if (remainingMs < hourMs) {
            // Menos de 1 hora: mostrar minutos (e segundos se relevante)
            uint64_t mins = remainingMs / minMs;
            uint64_t secs = (remainingMs % minMs) / 1000ULL;
            if (secs > 0)
                snprintf(buffer, sizeof(buffer), "%llum %llus", (unsigned long long)mins, (unsigned long long)secs);
            else
                snprintf(buffer, sizeof(buffer), "%llu minutos", (unsigned long long)mins);
        }
        else if (remainingMs < dayMs) {
            // Menos de 1 dia: mostrar horas e minutos
            uint64_t hours = remainingMs / hourMs;
            uint64_t mins  = (remainingMs % hourMs) / minMs;
            if (mins > 0)
                snprintf(buffer, sizeof(buffer), "%lluh %llum", (unsigned long long)hours, (unsigned long long)mins);
            else
                snprintf(buffer, sizeof(buffer), "%llu horas", (unsigned long long)hours);
        }
        else {
            // 1 dia ou mais: mostrar dias (floor, nao ceiling)
            uint64_t days = remainingMs / dayMs;
            if (!dateStr.empty())
                snprintf(buffer, sizeof(buffer), "%llu dias (%s)", (unsigned long long)days, dateStr.c_str());
            else
                snprintf(buffer, sizeof(buffer), "%llu dias", (unsigned long long)days);
        }

        return buffer;
    }

    // ========== Sistema de detecção de peers ==========

    // Atualizar o identificador do servidor atual (chamado externamente)
    void updateServerIdentifier(const std::string& serverIp) {
        std::lock_guard<std::mutex> lock(server_id_mutex);
        current_server_identifier = serverIp;
    }

    // Iniciar polling de peers
    void startPeerPolling() {
        if (peer_polling_running.exchange(true, std::memory_order_acq_rel)) {
            return; // Já está rodando
        }
        peer_polling_thread = std::thread([this]() {
            peerPollingLoop();
        });
        peer_polling_thread.detach();
    }

    // Parar polling de peers
    void stopPeerPolling() {
        peer_polling_running.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(peer_list_mutex);
            peer_list.clear();
        }
    }

    // Obter lista atual de peers
    std::vector<std::string> getPeers() {
        std::lock_guard<std::mutex> lock(peer_list_mutex);
        return peer_list;
    }

    // Verificar se um nome é um peer (case-insensitive)
    bool isPeer(const std::string& name) {
        std::lock_guard<std::mutex> lock(peer_list_mutex);
        for (const auto& peer : peer_list) {
            if (_stricmp(peer.c_str(), name.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }

    // Registrar callback chamado quando a lista de peers é atualizada
    void setPeerUpdateCallback(std::function<void(const std::vector<std::string>&)> callback) {
        peer_update_callback = std::move(callback);
    }

    // Registrar provider que retorna o IP/identificador do servidor atual
    void setServerIdentifierProvider(std::function<std::string()> provider) {
        server_identifier_provider = std::move(provider);
    }

    // Registrar provider que retorna o nome in-game (FiveM) do jogador local
    void setDisplayNameProvider(std::function<std::string()> provider) {
        display_name_provider = std::move(provider);
    }

    // Registrar provider que retorna se o "Identify ZeroM$ Users" (PeerDetection) está ativo.
    // Quando retorna false: o usuário não envia metadata de presenca (fica invisível para outros)
    // e não consulta peers (não vê outros usuários ZeroM$).
    void setPeerDetectionProvider(std::function<bool()> provider) {
        peer_detection_provider = std::move(provider);
    }
};

// Function to generate HWID (compatível com todos os sistemas Windows)
// IMPORTANTE: HWID DEVE ser determinístico - mesmo PC = mesmo HWID SEMPRE
inline std::string generate_hwid() {
    std::string hwid_source;
    DWORD volumeSerial = 0;
    bool hasStableId = false;

    // 1. Tentar obter serial do volume C: (mais confiável)
    if (GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0) && volumeSerial != 0) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << volumeSerial;
        hwid_source = ss.str();
        hasStableId = true;
        OutputDebugStringA(("[HWID] Volume serial C: " + hwid_source + "\n").c_str());
    }

    // 2. Fallback: tentar outras unidades
    if (!hasStableId) {
        char drives[] = "DEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; i < 24; i++) {
            std::string drive = std::string(1, drives[i]) + ":\\";
            if (GetVolumeInformationA(drive.c_str(), NULL, 0, &volumeSerial, NULL, NULL, NULL, 0) && volumeSerial != 0) {
                std::stringstream ss;
                ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << volumeSerial;
                hwid_source = ss.str();
                hasStableId = true;
                OutputDebugStringA(("[HWID] Volume serial " + drive + ": " + hwid_source + "\n").c_str());
                break;
            }
        }
    }

    // 3. Fallback: Nome do computador (estável enquanto não mudar o nome)
    if (!hasStableId) {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size) && size > 0) {
            // Usar SHA256 software para gerar um hash determinístico do nome
            std::string nameHash = SoftwareSHA256::hash(std::string(computerName, size));
            hwid_source = nameHash.substr(0, 16); // Primeiros 16 chars do hash
            hasStableId = true;
            OutputDebugStringA(("[HWID] Usando hash do nome do computador: " + hwid_source + "\n").c_str());
        }
    }

    // 4. Fallback: Username do Windows (também estável)
    if (!hasStableId) {
        char userName[256] = {};
        DWORD userSize = sizeof(userName);
        if (GetUserNameA(userName, &userSize) && userSize > 0) {
            std::string userHash = SoftwareSHA256::hash(std::string(userName, userSize));
            hwid_source = userHash.substr(0, 16);
            hasStableId = true;
            OutputDebugStringA(("[HWID] Usando hash do username: " + hwid_source + "\n").c_str());
        }
    }

    // 5. Último fallback: diretório Windows (sempre existe e é estável)
    if (!hasStableId) {
        char winDir[MAX_PATH] = {};
        UINT winDirLen = GetWindowsDirectoryA(winDir, MAX_PATH);
        if (winDirLen > 0) {
            std::string dirHash = SoftwareSHA256::hash(std::string(winDir, winDirLen));
            hwid_source = dirHash.substr(0, 16);
            hasStableId = true;
            OutputDebugStringA(("[HWID] Usando hash do diretorio Windows: " + hwid_source + "\n").c_str());
        }
    }

    // Se absolutamente nada funcionou (praticamente impossível)
    if (!hasStableId || hwid_source.empty()) {
        hwid_source = "FALLBACK00000000";
        OutputDebugStringA("[HWID] AVISO: Nenhum identificador estavel encontrado!\n");
    }

    OutputDebugStringA(("[HWID] Gerado: " + hwid_source + "\n").c_str());
    return hwid_source;
}