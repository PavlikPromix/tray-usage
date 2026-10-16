#pragma once
#include "proxy.h"
#include "resource.h"

namespace proxy {
struct Dialog {
    Config config;
    std::wstring error;
    Type previous = Type::system;
    void layout(HWND window) {
        const auto selected = static_cast<Type>(SendDlgItemMessageW(window, IDC_PROXY_TYPE, CB_GETCURSEL, 0, 0));
        const bool custom = selected == Type::http || selected == Type::socks5;
        const bool auth = custom && IsDlgButtonChecked(window, IDC_PROXY_AUTH) == BST_CHECKED;
        for (const int id : {IDC_PROXY_HOST, IDC_PROXY_PORT, IDC_PROXY_AUTH}) EnableWindow(GetDlgItem(window, id), custom);
        for (const int id : {IDC_PROXY_USER, IDC_PROXY_PASSWORD}) EnableWindow(GetDlgItem(window, id), auth);
        const int buttonY = 99 + (error.empty() ? 0 : 32);
        const auto place = [window](int id, int x, int y, int width, int height) {
            RECT rect{x, y, x + width, y + height};
            MapDialogRect(window, &rect);
            SetWindowPos(GetDlgItem(window, id), nullptr, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        };
        place(IDC_PROXY_ERROR, 8, 98, 238, 28);
        SetDlgItemTextW(window, IDC_PROXY_ERROR, error.c_str());
        ShowWindow(GetDlgItem(window, IDC_PROXY_ERROR), error.empty() ? SW_HIDE : SW_SHOW);
        place(IDOK, 118, buttonY, 64, 16);
        place(IDCANCEL, 188, buttonY, 58, 16);
        RECT desired{0, 0, 254, buttonY + 23}, frame{}, client{};
        MapDialogRect(window, &desired);
        GetWindowRect(window, &frame); GetClientRect(window, &client);
        SetWindowPos(window, nullptr, 0, 0, desired.right + frame.right - frame.left - client.right,
                     desired.bottom + frame.bottom - frame.top - client.bottom, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    static std::wstring text(HWND window, int id) {
        wchar_t buffer[512]{};
        const UINT length = GetDlgItemTextW(window, id, buffer, static_cast<int>(std::size(buffer)));
        std::wstring value(buffer, length);
        SecureZeroMemory(buffer, sizeof(buffer));
        return value;
    }
    void enable(HWND window) {
        const auto selected = static_cast<Type>(SendDlgItemMessageW(window, IDC_PROXY_TYPE, CB_GETCURSEL, 0, 0));
        const bool custom = selected == Type::http || selected == Type::socks5;
        if (selected != previous && custom) {
            const auto port = text(window, IDC_PROXY_PORT);
            if (port.empty() || (previous == Type::http && port == L"8080") || (previous == Type::socks5 && port == L"1080"))
                SetDlgItemTextW(window, IDC_PROXY_PORT, selected == Type::socks5 ? L"1080" : L"8080");
        }
        previous = selected;
        layout(window);
    }
    void init(HWND window) {
        for (const auto* name : {L"Системные настройки", L"Без прокси", L"HTTP", L"SOCKS5"})
            SendDlgItemMessageW(window, IDC_PROXY_TYPE, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        previous = config.type;
        SendDlgItemMessageW(window, IDC_PROXY_TYPE, CB_SETCURSEL, static_cast<WPARAM>(config.type), 0);
        SetDlgItemTextW(window, IDC_PROXY_HOST, config.host.c_str());
        SetDlgItemTextW(window, IDC_PROXY_PORT, std::to_wstring(config.port ? config.port : 8080).c_str());
        SetDlgItemTextW(window, IDC_PROXY_USER, config.username.c_str());
        SetDlgItemTextW(window, IDC_PROXY_PASSWORD, config.password.c_str());
        CheckDlgButton(window, IDC_PROXY_AUTH, config.authenticate ? BST_CHECKED : BST_UNCHECKED);
        for (const int id : {IDC_PROXY_HOST, IDC_PROXY_USER, IDC_PROXY_PASSWORD}) SendDlgItemMessageW(window, id, EM_SETLIMITTEXT, 255, 0);
        SendDlgItemMessageW(window, IDC_PROXY_PORT, EM_SETLIMITTEXT, 5, 0);
        enable(window);
        POINT point{}; GetCursorPos(&point);
        MONITORINFO monitor{sizeof(MONITORINFO), {}, {}, 0}; RECT rect{};
        if (GetMonitorInfoW(MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST), &monitor) && GetWindowRect(window, &rect)) {
            SetWindowPos(window, nullptr, monitor.rcWork.left + (monitor.rcWork.right - monitor.rcWork.left - rect.right + rect.left) / 2,
                monitor.rcWork.top + (monitor.rcWork.bottom - monitor.rcWork.top - rect.bottom + rect.top) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
    }
    bool submit(HWND window) {
        Config next;
        next.type = static_cast<Type>(SendDlgItemMessageW(window, IDC_PROXY_TYPE, CB_GETCURSEL, 0, 0));
        if (next.custom()) {
            next.host = text(window, IDC_PROXY_HOST);
            if (next.host.size() > 2 && next.host.front() == L'[' && next.host.back() == L']') next.host = next.host.substr(1, next.host.size() - 2);
            const auto port = text(window, IDC_PROXY_PORT);
            unsigned number = 0;
            for (const wchar_t c : port) { if (c < L'0' || c > L'9') { number = 0; break; } number = number * 10 + c - L'0'; }
            next.port = number <= 65535 ? static_cast<unsigned short>(number) : 0;
            next.authenticate = IsDlgButtonChecked(window, IDC_PROXY_AUTH) == BST_CHECKED;
            if (next.authenticate) { next.username = text(window, IDC_PROXY_USER); next.password = text(window, IDC_PROXY_PASSWORD); }
        }
        if (!save(next, error)) { layout(window); return false; }
        return true;
    }
    static INT_PTR CALLBACK procedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
        auto* self = reinterpret_cast<Dialog*>(GetWindowLongPtrW(window, DWLP_USER));
        try {
            if (message == WM_INITDIALOG) {
                self = reinterpret_cast<Dialog*>(lParam); SetWindowLongPtrW(window, DWLP_USER, lParam); self->init(window); return TRUE;
            }
            if (!self) return FALSE;
            if (message == WM_COMMAND) {
                const WORD id = LOWORD(wParam), event = HIWORD(wParam);
                if (id == IDCANCEL) { SetDlgItemTextW(window, IDC_PROXY_PASSWORD, L""); EndDialog(window, IDCANCEL); return TRUE; }
                if (id == IDOK) {
                    if (self->submit(window)) { SetDlgItemTextW(window, IDC_PROXY_PASSWORD, L""); EndDialog(window, IDOK); }
                    return TRUE;
                }
                if ((id == IDC_PROXY_TYPE && event == CBN_SELCHANGE) || id == IDC_PROXY_AUTH) { self->enable(window); return TRUE; }
            }
            if (message == WM_CLOSE) { SetDlgItemTextW(window, IDC_PROXY_PASSWORD, L""); EndDialog(window, IDCANCEL); return TRUE; }
        } catch (...) { MessageBoxW(window, L"Не удалось применить настройки прокси", L"TrayUsage", MB_OK | MB_ICONERROR); }
        return FALSE;
    }
};
inline bool showDialog(HWND owner) {
    Dialog state;
    load(state.config, state.error);
    const INT_PTR result = DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_PROXY), owner, Dialog::procedure, reinterpret_cast<LPARAM>(&state));
    if (result == -1) MessageBoxW(owner, L"Не удалось открыть настройки прокси", L"TrayUsage", MB_OK | MB_ICONERROR);
    return result == IDOK;
}
}
