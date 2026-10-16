#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace proxy {
constexpr wchar_t settingsKey[] = L"Software\\TrayUsage";
enum class Type : DWORD { system, direct, http, socks5 };
template<class T> inline void wipe(T& value) {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(value[0]));
    value.clear();
}
struct Config {
    Type type = Type::system;
    std::wstring host;
    unsigned short port = 8080;
    bool authenticate = false;
    std::wstring username, password;
    Config() = default;
    Config(const Config&) = default;
    Config& operator=(const Config& other) {
        if (this != &other) {
            wipe(username); wipe(password);
            type = other.type; host = other.host; port = other.port; authenticate = other.authenticate;
            username = other.username; password = other.password;
        }
        return *this;
    }
    ~Config() { wipe(username); wipe(password); }
    bool custom() const { return type == Type::http || type == Type::socks5; }
};
struct Bytes {
    std::vector<BYTE> value;
    ~Bytes() { wipe(value); }
};
inline std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!count) return {};
    std::string out(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), out.data(), count, nullptr, nullptr);
    return out;
}
inline std::wstring validate(const Config& config) {
    if (config.type > Type::socks5) return L"Неизвестный тип прокси";
    if (!config.custom()) return {};
    if (config.host.empty() || config.host.size() > 253) return L"Укажите адрес прокси (не более 253 символов)";
    if (!config.port) return L"Укажите порт от 1 до 65535";
    if (!std::all_of(config.host.begin(), config.host.end(), [](wchar_t c) {
        return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' || c == L':';
    })) return L"Адрес: IP или имя сервера без схемы, порта и пути";
    if (config.host.find(L':') != std::wstring::npos) {
        IN6_ADDR address{};
        if (InetPtonW(AF_INET6, config.host.c_str(), &address) != 1) return L"Некорректный IPv6-адрес";
    }
    if (!config.authenticate) return {};
    if (config.username.empty()) return L"Укажите логин прокси";
    for (const auto* value : {&config.username, &config.password}) {
        if (value->size() > 255 || std::any_of(value->begin(), value->end(), [](wchar_t c) { return c < 32 || c == 127; }))
            return L"Логин и пароль: до 255 байт, без управляющих символов";
        auto encoded = utf8(*value);
        const bool valid = (value->empty() || !encoded.empty()) && encoded.size() <= 255;
        wipe(encoded);
        if (!valid) return L"Логин и пароль: не более 255 байт UTF-8";
    }
    if (config.type == Type::socks5 && config.password.empty()) return L"Для авторизации SOCKS5 укажите пароль";
    if (config.type == Type::http && config.username.find(L':') != std::wstring::npos) return L"Логин HTTP-прокси не должен содержать двоеточие";
    return {};
}
inline std::wstring endpoint(const Config& config) {
    return (config.host.find(L':') == std::wstring::npos ? config.host : L"[" + config.host + L"]") + L":" + std::to_wstring(config.port);
}
inline void appendNumber(std::vector<BYTE>& bytes, DWORD value) {
    for (unsigned i = 0; i < 4; ++i) bytes.push_back(static_cast<BYTE>(value >> (i * 8)));
}
inline void appendString(std::vector<BYTE>& bytes, const std::wstring& value) {
    appendNumber(bytes, static_cast<DWORD>(value.size()));
    for (const wchar_t c : value) { bytes.push_back(static_cast<BYTE>(c)); bytes.push_back(static_cast<BYTE>(c >> 8)); }
}
inline bool decode(const std::vector<BYTE>& bytes, Config& out) {
    size_t pos = 0;
    bool valid = true;
    const auto number = [&]() -> DWORD {
        if (bytes.size() - pos < 4) { valid = false; return 0; }
        DWORD value = 0;
        for (unsigned i = 0; i < 4; ++i) value |= static_cast<DWORD>(bytes[pos++]) << (i * 8);
        return value;
    };
    const auto string = [&]() {
        std::wstring value;
        const DWORD count = number();
        if (!valid || count > 255 || count > (bytes.size() - pos) / 2) { valid = false; return value; }
        for (DWORD i = 0; i < count; ++i) {
            const wchar_t c = static_cast<wchar_t>(bytes[pos] | (static_cast<unsigned>(bytes[pos + 1]) << 8));
            pos += 2;
            if (!c) valid = false;
            value += c;
        }
        return value;
    };
    if (number() != 1) return false;
    out.type = static_cast<Type>(number());
    const DWORD port = number(), auth = number();
    out.port = static_cast<unsigned short>(port); out.authenticate = auth == 1;
    out.host = string(); out.username = string(); out.password = string();
    return valid && pos == bytes.size() && port <= 65535 && auth <= 1 && validate(out).empty();
}
// One atomic registry value; DPAPI binds all settings, including credentials, to the current Windows user.
inline bool save(const Config& config, std::wstring& error, const wchar_t* key = settingsKey) {
    error = validate(config);
    if (!error.empty()) return false;
    if (config.type == Type::system) {
        const LSTATUS status = RegDeleteKeyValueW(HKEY_CURRENT_USER, key, L"ProxyConfig");
        if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return true;
        error = L"Не удалось удалить настройки прокси из реестра"; return false;
    }
    Bytes plain;
    plain.value.reserve(1600);
    appendNumber(plain.value, 1); appendNumber(plain.value, static_cast<DWORD>(config.type));
    appendNumber(plain.value, config.custom() ? config.port : 0);
    appendNumber(plain.value, config.custom() && config.authenticate ? 1 : 0);
    appendString(plain.value, config.custom() ? config.host : L"");
    appendString(plain.value, config.custom() && config.authenticate ? config.username : L"");
    appendString(plain.value, config.custom() && config.authenticate ? config.password : L"");
    DATA_BLOB input{static_cast<DWORD>(plain.value.size()), plain.value.data()}, encrypted{};
    if (!CryptProtectData(&input, L"TrayUsage proxy", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) {
        error = L"Windows не удалось защитить настройки прокси"; return false;
    }
    const LSTATUS status = RegSetKeyValueW(HKEY_CURRENT_USER, key, L"ProxyConfig", REG_BINARY, encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    if (status != ERROR_SUCCESS) { error = L"Не удалось сохранить прокси в реестре"; return false; }
    return true;
}
inline bool load(Config& config, std::wstring& error, const wchar_t* key = settingsKey) {
    config = Config{}; error.clear();
    DWORD size = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, key, L"ProxyConfig", RRF_RT_REG_BINARY, nullptr, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return true;
    error = L"Не удалось прочитать прокси — откройте «Прокси…» и сохраните настройки";
    if (status != ERROR_SUCCESS || !size || size > 16384) return false;
    Bytes encrypted;
    encrypted.value.resize(size);
    status = RegGetValueW(HKEY_CURRENT_USER, key, L"ProxyConfig", RRF_RT_REG_BINARY, nullptr, encrypted.value.data(), &size);
    if (status != ERROR_SUCCESS) return false;
    DATA_BLOB input{size, encrypted.value.data()}, plain{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return false;
    Bytes decoded;
    decoded.value.assign(plain.pbData, plain.pbData + plain.cbData);
    SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData);
    Config parsed;
    if (!decode(decoded.value, parsed)) return false;
    config = parsed; error.clear(); return true;
}
}
