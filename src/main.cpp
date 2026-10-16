#include "socks5.h"
#include "proxy_dialog.h"
#include <windowsx.h>
#include <shellapi.h>
#include <winhttp.h>
#include <algorithm>
#include <atomic>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include "usage.h"

namespace {
constexpr wchar_t windowClass[] = L"TrayUsage.NotificationWindow";
constexpr wchar_t settingsKey[] = L"Software\\TrayUsage";
constexpr UINT trayMessage = WM_APP + 1;
constexpr UINT resultMessage = WM_APP + 2;
constexpr UINT shortCommand = 1001, weekCommand = 1002, refreshCommand = 1003, exitCommand = 1004;
constexpr UINT proxyCommand = 1005;
constexpr DWORD pollMs = 60 * 1000;
constexpr size_t maxBody = 1024 * 1024;

struct WinHandle {
    HANDLE value = nullptr;
    explicit WinHandle(HANDLE h = nullptr) : value(h) {}
    ~WinHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
};
struct HttpHandle {
    HINTERNET value = nullptr;
    explicit HttpHandle(HINTERNET h) : value(h) {}
    ~HttpHandle() { if (value) WinHttpCloseHandle(value); }
    HttpHandle(const HttpHandle&) = delete;
    HttpHandle& operator=(const HttpHandle&) = delete;
};
template<class String> struct Secret {
    String value;
    ~Secret() { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(typename String::value_type)); }
};
struct FetchResult {
    bool ok = false;
    usage::Snapshot snapshot;
    std::wstring error;
    DWORD retryMs = pollMs;
    std::time_t fetchedAt = 0;
    unsigned settingsVersion = 0;
};

std::wstring environment(const wchar_t* name) {
    const DWORD length = GetEnvironmentVariableW(name, nullptr, 0);
    if (!length) return {};
    std::wstring value(length, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), length);
    if (!written || written >= length) return {};
    value.resize(written);
    return value;
}
std::wstring authPath() {
    auto home = environment(L"CODEX_HOME");
    if (home.empty()) { home = environment(L"USERPROFILE"); if (home.empty()) return {}; home += L"\\.codex"; }
    return home + L"\\auth.json";
}
bool readAuth(Secret<std::string>& body) {
    const auto path = authPath();
    WinHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>(maxBody)) return false;
    body.value.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    return ReadFile(file.value, body.value.data(), static_cast<DWORD>(body.value.size()), &read, nullptr) && read == body.value.size();
}
bool headerSafe(const std::string& value) {
    return !value.empty() && value.size() < 32768 && std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 0x21 && c <= 0x7e; });
}
std::wstring asciiWide(const std::string& value) { return std::wstring(value.begin(), value.end()); }
bool sendRequest(HINTERNET request, const std::wstring& headers, const proxy::Config& config, DWORD& status, std::wstring& error) {
    const bool credentials = config.type == proxy::Type::http && config.authenticate;
    DWORD policy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &policy, sizeof(policy))) {
        error = L"Не удалось настроить авторизацию WinHTTP"; return false;
    }
    if (credentials && !WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC,
                                              config.username.c_str(), config.password.c_str(), nullptr)) {
        error = L"Не удалось настроить авторизацию HTTP-прокси"; return false;
    }
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(headers.size()), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) {
            const DWORD code = GetLastError();
            if (code == ERROR_WINHTTP_RESEND_REQUEST) continue;
            error = code == ERROR_WINHTTP_LOGIN_FAILURE ? L"HTTP-прокси: проверьте логин и пароль" : L"Ошибка сети (" + std::to_wstring(code) + L")";
            return false;
        }
        DWORD size = sizeof(status);
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
            error = L"Нет HTTP статуса"; return false;
        }
        if (status != 407) return true;
        if (!credentials) { error = L"HTTP-прокси требует авторизацию — откройте «Прокси…»"; return false; }
        DWORD supported = 0, first = 0, target = 0;
        if (!WinHttpQueryAuthSchemes(request, &supported, &first, &target) || target != WINHTTP_AUTH_TARGET_PROXY) break;
        DWORD scheme = 0;
        for (const DWORD candidate : {WINHTTP_AUTH_SCHEME_NEGOTIATE, WINHTTP_AUTH_SCHEME_NTLM, WINHTTP_AUTH_SCHEME_DIGEST, WINHTTP_AUTH_SCHEME_BASIC}) {
            if (supported & candidate) { scheme = candidate; break; }
        }
        if (!scheme || !WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, scheme, config.username.c_str(), config.password.c_str(), nullptr)) break;
    }
    error = L"HTTP-прокси: авторизация не удалась"; return false;
}
FetchResult fetchUsage() {
    FetchResult result;
    proxy::Config config;
    if (!proxy::load(config, result.error)) return result;
    Secret<std::string> auth;
    if (!readAuth(auth)) { result.error = L"Нет auth.json — войдите в Codex"; return result; }
    const auto root = json::parse(auth.value);
    const auto tokens = root.get("tokens");
    Secret<std::string> token{tokens.get("access_token").string()};
    const auto account = tokens.get("account_id").string();
    if (!headerSafe(token.value) || !headerSafe(account)) {
        result.error = L"Нужен вход в Codex через ChatGPT";
        return result;
    }
    std::unique_ptr<proxy::SocksBridge> bridge;
    DWORD access = config.type == proxy::Type::direct ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
    std::wstring proxyAddress;
    if (config.type == proxy::Type::http) proxyAddress = proxy::endpoint(config);
    if (config.type == proxy::Type::socks5) {
        bridge = std::make_unique<proxy::SocksBridge>();
        if (!bridge->start(config)) { result.error = L"Не удалось создать SOCKS5-туннель"; return result; }
        proxyAddress = bridge->endpoint();
    }
    if (config.custom()) access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    HttpHandle session(WinHttpOpen(L"codex-cli (TrayUsage/1.1.0)", access,
                                  proxyAddress.empty() ? WINHTTP_NO_PROXY_NAME : proxyAddress.c_str(), WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.value || !WinHttpSetTimeouts(session.value, 4000, 4000, 4000, 8000)) {
        result.error = L"Не удалось открыть WinHTTP"; return result;
    }
    HttpHandle connection(WinHttpConnect(session.value, L"chatgpt.com", INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connection.value) { result.error = L"Нет соединения с ChatGPT"; return result; }
    HttpHandle request(WinHttpOpenRequest(connection.value, L"GET", L"/backend-api/wham/usage", nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request.value) { result.error = L"Не удалось создать HTTPS запрос"; return result; }
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy))) {
        result.error = L"Не удалось настроить HTTPS"; return result;
    }
    // Credentials only go to the fixed HTTPS origin. TLS verification stays enabled.
    Secret<std::wstring> headers{L"Authorization: Bearer " + asciiWide(token.value) + L"\r\nChatGPT-Account-Id: " + asciiWide(account) + L"\r\nAccept: application/json\r\nCache-Control: no-cache\r\n"};
    DWORD status = 0;
    if (!sendRequest(request.value, headers.value, config, status, result.error)) {
        if (bridge) { const auto detail = bridge->error(); if (!detail.empty()) result.error = detail; }
        return result;
    }
    if (status != 200) {
        if (status == 401) result.error = L"Сессия истекла — обновите вход в Codex";
        else if (status == 403) result.error = L"ChatGPT отказал в доступе (403)";
        else result.error = L"Ошибка HTTP " + std::to_wstring(status);
        if (status == 429 || status == 503) {
            DWORD seconds = 0, length = sizeof(seconds);
            if (WinHttpQueryHeaders(request.value, WINHTTP_QUERY_RETRY_AFTER | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &seconds, &length, WINHTTP_NO_HEADER_INDEX))
                result.retryMs = std::max(pollMs, std::min(seconds, 86400UL) * 1000UL);
        }
        return result;
    }
    std::string body;
    char buffer[8192];
    const ULONGLONG deadline = GetTickCount64() + 15000;
    for (;;) {
        DWORD count = 0;
        if (GetTickCount64() > deadline || !WinHttpReadData(request.value, buffer, sizeof(buffer), &count)) {
            result.error = L"Не удалось прочитать ответ"; return result;
        }
        if (!count) break;
        if (body.size() + count > maxBody) { result.error = L"Слишком большой ответ сервера"; return result; }
        body.append(buffer, count);
    }
    result.snapshot = usage::parse(body);
    result.fetchedAt = std::time(nullptr);
    result.ok = true;
    return result;
}
FetchResult fetchSafely() {
    try { return fetchUsage(); }
    catch (const std::exception&) { FetchResult result; result.error = L"Не удалось прочитать формат данных Codex"; return result; }
}

std::wstring resetLabel(std::int64_t timestamp, bool date) {
    if (!timestamp) return L"сброс: нет данных";
    const std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm local{};
    if (localtime_s(&local, &time)) return L"сброс: нет данных";
    wchar_t buffer[40]{};
    std::wcsftime(buffer, std::size(buffer), date ? L"%d.%m %H:%M" : L"%H:%M", &local);
    return L"сброс " + std::wstring(buffer);
}
std::wstring windowLabel(const std::optional<usage::Window>& window, bool date) {
    if (!window) return L"нет данных";
    return std::to_wstring(window->remaining()) + L"% · " + resetLabel(window->reset, date);
}

int iconSize() {
    const HWND taskbar = FindWindowW(L"Shell_TrayWnd", nullptr);
    const UINT dpi = taskbar ? GetDpiForWindow(taskbar) : GetDpiForSystem();
    return std::clamp(GetSystemMetricsForDpi(SM_CXSMICON, dpi ? dpi : 96), 16, 64);
}
HICON makeIcon(const std::wstring& text, int remaining, bool stale, int side = iconSize()) {
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = side; info.bmiHeader.biHeight = -side;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32; info.bmiHeader.biCompression = BI_RGB;
    void* pixels = nullptr;
    HDC dc = CreateCompatibleDC(nullptr);
    if (!dc) return nullptr;
    HBITMAP bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &pixels, nullptr, 0);
    BYTE maskPixels[64 * 8]{};
    HBITMAP mask = CreateBitmap(side, side, 1, 1, maskPixels);
    if (!bitmap || !mask) { if (bitmap) DeleteObject(bitmap); if (mask) DeleteObject(mask); DeleteDC(dc); return nullptr; }
    const auto oldBitmap = SelectObject(dc, bitmap);
    ZeroMemory(pixels, static_cast<size_t>(side) * side * 4);
    HFONT font = nullptr;
    HGDIOBJ oldFont = nullptr;
    // Fit 100 as well as two-digit values into the real notification icon size.
    for (int height = side; height >= 6; --height) {
        font = CreateFontW(-height, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        if (!font) break;
        const auto previous = SelectObject(dc, font);
        if (!oldFont) oldFont = previous;
        SIZE extent{};
        GetTextExtentPoint32W(dc, text.c_str(), static_cast<int>(text.size()), &extent);
        if (extent.cx <= side && extent.cy <= side - 2) break;
        SelectObject(dc, oldFont); DeleteObject(font); font = nullptr;
    }
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255));
    RECT rect{0, -1, side, side - 2};
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    GdiFlush();
    COLORREF color = stale || remaining < 0 ? RGB(145, 145, 145) : remaining <= 5 ? RGB(235, 70, 70) : remaining <= 20 ? RGB(220, 145, 25) : RGB(35, 175, 120);
    auto* bits = static_cast<DWORD*>(pixels);
    const DWORD rgb = (static_cast<DWORD>(GetRValue(color)) << 16) | (static_cast<DWORD>(GetGValue(color)) << 8) | GetBValue(color);
    for (int i = 0; i < side * side; ++i) {
        const DWORD alpha = bits[i] & 255;
        bits[i] = (alpha << 24) | ((GetRValue(color) * alpha / 255) << 16) |
                  ((GetGValue(color) * alpha / 255) << 8) | (GetBValue(color) * alpha / 255);
    }
    if (remaining >= 0) {
        const int width = (side - 2) * remaining / 100;
        for (int y = side - 2; y < side; ++y)
            for (int x = 1; x < side - 1; ++x) bits[y * side + x] = x <= width ? 0xff000000 | rgb : 0x50101010;
    }
    if (stale) for (int y = 0; y < std::max(2, side / 6); ++y)
        for (int x = side - std::max(2, side / 6); x < side; ++x) bits[y * side + x] = 0xffffac33;
    if (oldFont) SelectObject(dc, oldFont);
    if (font) DeleteObject(font);
    SelectObject(dc, oldBitmap);
    ICONINFO iconInfo{}; iconInfo.fIcon = TRUE; iconInfo.hbmColor = bitmap; iconInfo.hbmMask = mask;
    HICON icon = CreateIconIndirect(&iconInfo);
    DeleteObject(mask); DeleteObject(bitmap); DeleteDC(dc);
    return icon;
}

struct App {
    HWND window = nullptr;
    UINT taskbarCreated = 0;
    NOTIFYICONDATAW tray{};
    HICON icon = nullptr;
    bool trayAdded = false;
    bool weekly = false;
    bool received = false;
    bool stale = false;
    usage::Snapshot snapshot;
    std::wstring error;
    std::time_t fetchedAt = 0;
    WinHandle stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    WinHandle refresh{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
    std::atomic<bool> busy{false};
    std::atomic<unsigned> settingsVersion{0};
    std::atomic<bool> forceRefresh{false};
    std::mutex resultMutex;
    FetchResult pending;
    std::thread worker;

    ~App() {
        if (stop.value) SetEvent(stop.value);
        if (worker.joinable()) worker.join();
        if (trayAdded) Shell_NotifyIconW(NIM_DELETE, &tray);
        if (icon) DestroyIcon(icon);
    }
    void startWorker() {
        worker = std::thread([this] {
            const HANDLE events[] = {stop.value, refresh.value};
            ULONGLONG nextAttempt = 0, lastAttempt = 0;
            unsigned failures = 0;
            for (;;) {
                const ULONGLONG now = GetTickCount64();
                const DWORD timeout = nextAttempt > now ? static_cast<DWORD>(std::min<ULONGLONG>(nextAttempt - now, MAXDWORD - 1)) : 0;
                const DWORD event = WaitForMultipleObjects(2, events, FALSE, timeout);
                if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) return;
                const bool forced = forceRefresh.exchange(false);
                if (!forced && lastAttempt && GetTickCount64() - lastAttempt < 10000) continue;
                lastAttempt = GetTickCount64();
                busy.store(true);
                const unsigned version = settingsVersion.load();
                auto result = fetchSafely();
                result.settingsVersion = version;
                if (settingsVersion.load() != version) { busy.store(false); nextAttempt = 0; continue; }
                failures = result.ok ? 0 : std::min(failures + 1, 4U);
                DWORD delay = result.ok ? pollMs : std::max(result.retryMs, pollMs * (1UL << (failures - 1)));
                nextAttempt = GetTickCount64() + delay;
                {
                    std::lock_guard<std::mutex> lock(resultMutex);
                    pending = std::move(result);
                }
                busy.store(false);
                if (WaitForSingleObject(stop.value, 0) == WAIT_OBJECT_0) return;
                PostMessageW(window, resultMessage, 0, 0);
            }
        });
    }
    void receive() {
        FetchResult result;
        { std::lock_guard<std::mutex> lock(resultMutex); result = pending; }
        if (result.settingsVersion != settingsVersion.load()) return;
        received = true;
        if (result.ok) { snapshot = result.snapshot; fetchedAt = result.fetchedAt; stale = false; error.clear(); }
        else { stale = true; error = result.error; }
        updateIcon();
    }
    void updateIcon() {
        const auto& selected = weekly ? snapshot.weeklyWindow : snapshot.shortWindow;
        const int remaining = selected ? selected->remaining() : -1;
        const std::wstring text = selected ? std::to_wstring(remaining) : received ? L"?" : L"···";
        HICON replacement = makeIcon(text, remaining, stale);
        if (replacement) { const HICON old = icon; icon = replacement; if (old) DestroyIcon(old); }
        tray = {}; tray.cbSize = sizeof(tray); tray.hWnd = window; tray.uID = 1;
        tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
        tray.uCallbackMessage = trayMessage; tray.hIcon = icon;
        std::wstring tip = L"5 ч: " + windowLabel(snapshot.shortWindow, false) +
            L"\nНеделя: " + windowLabel(snapshot.weeklyWindow, true);
        if (stale) tip = L"Устарело: " + error + L"\n" + tip;
        wcsncpy_s(tray.szTip, tip.c_str(), _TRUNCATE);
        const bool success = Shell_NotifyIconW(trayAdded ? NIM_MODIFY : NIM_ADD, &tray) != FALSE;
        if (success) {
            if (!trayAdded) { tray.uVersion = NOTIFYICON_VERSION_4; Shell_NotifyIconW(NIM_SETVERSION, &tray); }
            trayAdded = true; KillTimer(window, 1);
        } else {
            // Explorer may not be ready at logon; retry only while registration fails.
            trayAdded = false; SetTimer(window, 1, 5000, nullptr);
        }
    }
    void select(bool value) {
        weekly = value;
        const DWORD seconds = weekly ? usage::oneWeek : usage::fiveHours;
        RegSetKeyValueW(HKEY_CURRENT_USER, settingsKey, L"WindowSeconds", REG_DWORD, &seconds, sizeof(seconds));
        updateIcon();
    }
    void menu(POINT point) {
        HMENU popup = CreatePopupMenu();
        if (!popup) return;
        AppendMenuW(popup, MF_STRING | MF_DISABLED, 0, L"Codex · осталось");
        AppendMenuW(popup, MF_STRING, shortCommand, (L"5 часов: " + windowLabel(snapshot.shortWindow, true)).c_str());
        AppendMenuW(popup, MF_STRING, weekCommand, (L"Неделя: " + windowLabel(snapshot.weeklyWindow, true)).c_str());
        CheckMenuRadioItem(popup, shortCommand, weekCommand, weekly ? weekCommand : shortCommand, MF_BYCOMMAND);
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        if (stale) AppendMenuW(popup, MF_STRING | MF_DISABLED, 0, error.c_str());
        if (fetchedAt) {
            const auto time = resetLabel(fetchedAt, true);
            AppendMenuW(popup, MF_STRING | MF_DISABLED, 0, (L"Обновлено " + time.substr(6)).c_str());
        }
        AppendMenuW(popup, MF_STRING | (busy.load() ? MF_GRAYED : 0), refreshCommand, busy.load() ? L"Обновляется…" : L"Обновить");
        AppendMenuW(popup, MF_STRING, proxyCommand, L"Прокси…");
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(popup, MF_STRING, exitCommand, L"Выход");
        SetForegroundWindow(window);
        const UINT command = static_cast<UINT>(TrackPopupMenuEx(popup, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, point.x, point.y, window, nullptr));
        DestroyMenu(popup); PostMessageW(window, WM_NULL, 0, 0);
        if (command) SendMessageW(window, WM_COMMAND, command, 0);
    }
};
LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        app = static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
        app->window = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
    }
    if (!app) return DefWindowProcW(window, message, wParam, lParam);
    if (message == app->taskbarCreated) { app->trayAdded = false; app->updateIcon(); return 0; }
    switch (message) {
    case trayMessage: {
        const UINT event = LOWORD(lParam);
        if (event == WM_CONTEXTMENU || event == NIN_KEYSELECT || event == NIN_SELECT) {
            POINT point{GET_X_LPARAM(wParam), GET_Y_LPARAM(wParam)};
            if (point.x == -1 && point.y == -1) GetCursorPos(&point);
            app->menu(point);
        }
        return 0;
    }
    case resultMessage: app->receive(); return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case shortCommand: app->select(false); break;
        case weekCommand: app->select(true); break;
        case refreshCommand: if (!app->busy.load()) SetEvent(app->refresh.value); break;
        case proxyCommand:
            if (proxy::showDialog(window)) { ++app->settingsVersion; app->forceRefresh.store(true); SetEvent(app->refresh.value); }
            break;
        case exitCommand: SendMessageW(window, WM_CLOSE, 0, 0); break;
        }
        return 0;
    case WM_TIMER: if (wParam == 1) app->updateIcon(); return 0;
    case WM_SETTINGCHANGE: case WM_DPICHANGED: app->updateIcon(); return 0;
    case WM_POWERBROADCAST:
        if (wParam == PBT_APMRESUMEAUTOMATIC) SetEvent(app->refresh.value);
        return TRUE;
    case WM_QUERYENDSESSION: return TRUE;
    case WM_ENDSESSION: if (wParam) DestroyWindow(window); return 0;
    case WM_CLOSE:
        if (const HWND popup = GetLastActivePopup(window); popup != window && GetWindow(popup, GW_OWNER) == window) EndDialog(popup, IDCANCEL);
        SetEvent(app->stop.value);
        if (app->trayAdded) { Shell_NotifyIconW(NIM_DELETE, &app->tray); app->trayAdded = false; }
        DestroyWindow(window); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    default: return DefWindowProcW(window, message, wParam, lParam);
    }
}
void writeOutput(const std::string& text) {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(output, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
}
int check() {
    const auto result = fetchSafely();
    if (!result.ok) {
        // Error strings are fixed local messages, never server bodies or credentials.
        const int size = WideCharToMultiByte(CP_UTF8, 0, result.error.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string error(static_cast<size_t>(std::max(size, 1)), '\0');
        WideCharToMultiByte(CP_UTF8, 0, result.error.c_str(), -1, error.data(), static_cast<int>(error.size()), nullptr, nullptr);
        if (!error.empty()) error.pop_back();
        writeOutput("{\"ok\":false,\"error\":\"" + error + "\"}\n"); return 1;
    }
    const auto field = [](const std::optional<usage::Window>& window) {
        return window ? "{\"remainingPercent\":" + std::to_string(window->remaining()) + ",\"resetsAt\":" + std::to_string(window->reset) + "}" : std::string("null");
    };
    writeOutput("{\"ok\":true,\"fiveHour\":" + field(result.snapshot.shortWindow) + ",\"weekly\":" + field(result.snapshot.weeklyWindow) + "}\n");
    return 0;
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    int count = 0;
    LPWSTR* args = CommandLineToArgvW(GetCommandLineW(), &count);
    const bool diagnostic = args && count == 2 && std::wstring_view(args[1]) == L"--check";
    const bool quit = args && count == 2 && std::wstring_view(args[1]) == L"--quit";
    const bool invalidArgs = count > 1 && !diagnostic && !quit;
    if (args) LocalFree(args);
    if (diagnostic) return check();
    if (quit) { if (const HWND existing = FindWindowW(windowClass, nullptr)) PostMessageW(existing, WM_CLOSE, 0, 0); return 0; }
    if (invalidArgs) { writeOutput("Usage: TrayUsage.exe [--check | --quit]\n"); return 2; }
    WinHandle instanceMutex(CreateMutexW(nullptr, FALSE, L"Local\\TrayUsage.SingleInstance"));
    const DWORD mutexError = GetLastError();
    if (!instanceMutex.value) return 2;
    if (mutexError == ERROR_ALREADY_EXISTS) return 0;
    try {
        App app;
        if (!app.stop.value || !app.refresh.value) return 2;
        DWORD seconds = 0, size = sizeof(seconds);
        if (RegGetValueW(HKEY_CURRENT_USER, settingsKey, L"WindowSeconds", RRF_RT_REG_DWORD, nullptr, &seconds, &size) == ERROR_SUCCESS)
            app.weekly = seconds == usage::oneWeek;
        app.taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
        WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = windowProc; wc.hInstance = instance; wc.lpszClassName = windowClass;
        if (!app.taskbarCreated || !RegisterClassExW(&wc)) return 2;
        // A hidden top-level window receives Explorer restart and power broadcasts.
        if (!CreateWindowExW(WS_EX_TOOLWINDOW, windowClass, L"TrayUsage", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr, instance, &app)) return 2;
        app.updateIcon(); app.startWorker();
        MSG message{};
        int status = 0;
        while ((status = static_cast<int>(GetMessageW(&message, nullptr, 0, 0))) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
        if (IsWindow(app.window)) DestroyWindow(app.window);
        return status == -1 ? 2 : 0;
    } catch (const std::exception&) { return 2; }
}
