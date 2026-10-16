// Exercise the actual Win32 icon code without starting the network worker.
#include "../src/main.cpp"
#include <iostream>
#include <vector>

namespace {
bool verifyIcon(const wchar_t* text, int remaining, bool stale, int side) {
    HICON icon = makeIcon(text, remaining, stale, side);
    if (!icon) return false;
    ICONINFO info{};
    const bool obtained = GetIconInfo(icon, &info) != FALSE;
    bool valid = obtained;
    if (obtained) {
        BITMAPINFO format{};
        format.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        format.bmiHeader.biWidth = side; format.bmiHeader.biHeight = -side;
        format.bmiHeader.biPlanes = 1; format.bmiHeader.biBitCount = 32;
        HDC dc = CreateCompatibleDC(nullptr);
        std::vector<DWORD> pixels(static_cast<size_t>(side) * side);
        valid = dc && GetDIBits(dc, info.hbmColor, 0, side, pixels.data(), &format, DIB_RGB_COLORS) != 0;
        bool ink = false, transparent = false;
        for (const DWORD pixel : pixels) {
            const DWORD alpha = pixel >> 24;
            ink |= alpha > 0; transparent |= alpha == 0;
            valid &= ((pixel >> 16) & 255) <= alpha && ((pixel >> 8) & 255) <= alpha && (pixel & 255) <= alpha;
        }
        valid &= ink && transparent;
        if (dc) DeleteDC(dc);
        DeleteObject(info.hbmColor); DeleteObject(info.hbmMask);
    }
    DestroyIcon(icon);
    return valid;
}
bool savePreview(const wchar_t* path) {
    constexpr int cell = 64, columns = 8, width = cell * columns, height = 2 * cell;
    BITMAPINFO format{};
    format.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    format.bmiHeader.biWidth = width; format.bmiHeader.biHeight = -height;
    format.bmiHeader.biPlanes = 1; format.bmiHeader.biBitCount = 32;
    void* pixels = nullptr;
    HDC dc = CreateCompatibleDC(nullptr);
    if (!dc) return false;
    HBITMAP bitmap = CreateDIBSection(dc, &format, DIB_RGB_COLORS, &pixels, nullptr, 0);
    if (!bitmap) { DeleteDC(dc); return false; }
    const auto old = SelectObject(dc, bitmap);
    const wchar_t* labels[] = {L"100", L"59", L"40", L"20", L"5", L"0", L"40", L"?"};
    const int values[] = {100, 59, 40, 20, 5, 0, 40, -1};
    for (int row = 0; row < 2; ++row) {
        HBRUSH background = CreateSolidBrush(row ? RGB(245, 245, 245) : RGB(25, 25, 25));
        RECT area{0, row * cell, width, (row + 1) * cell}; FillRect(dc, &area, background); DeleteObject(background);
        for (int column = 0; column < columns; ++column) {
            // Actual 16px output, displayed at 3x for inspection.
            HICON icon = makeIcon(labels[column], values[column], column == 6, 16);
            DrawIconEx(dc, column * cell + 8, row * cell + 8, icon, 48, 48, 0, nullptr, DI_NORMAL);
            DestroyIcon(icon);
        }
    }
    GdiFlush();
    BITMAPFILEHEADER header{}; header.bfType = 0x4d42;
    header.bfOffBits = sizeof(header) + sizeof(BITMAPINFOHEADER);
    header.bfSize = header.bfOffBits + width * height * 4;
    WinHandle file(CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    bool saved = file.value != INVALID_HANDLE_VALUE;
    DWORD written = 0;
    if (saved) saved = WriteFile(file.value, &header, sizeof(header), &written, nullptr) &&
                      WriteFile(file.value, &format.bmiHeader, sizeof(BITMAPINFOHEADER), &written, nullptr) &&
                      WriteFile(file.value, pixels, width * height * 4, &written, nullptr);
    SelectObject(dc, old); DeleteObject(bitmap); DeleteDC(dc);
    return saved;
}
}
int main() {
    for (const int side : {16, 20, 24, 32, 48, 64}) {
        for (const int value : {0, 5, 20, 40, 59, 99, 100}) {
            if (!verifyIcon(std::to_wstring(value).c_str(), value, false, side) ||
                !verifyIcon(std::to_wstring(value).c_str(), value, true, side)) return 1;
        }
        if (!verifyIcon(L"?", -1, true, side)) return 1;
    }
    const DWORD handles = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    const DWORD userHandles = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    for (int i = 0; i < 1000; ++i) { HICON icon = makeIcon(L"100", 100, false, 16); if (!icon) return 1; DestroyIcon(icon); }
    if (GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) != handles ||
        GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) != userHandles) {
        std::cerr << "Win32 icon resource leak\n"; return 1;
    }
    if (!savePreview(L"icon-preview.bmp")) return 1;
    std::cout << "Native icon tests passed (6 sizes, alpha, 1000 redraws without leaks)\n";
    return 0;
}
