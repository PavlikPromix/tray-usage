#pragma once
#include "proxy.h"
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

namespace proxy {
struct Winsock {
    bool ready = false;
    Winsock() { WSADATA data{}; ready = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
    ~Winsock() { if (ready) WSACleanup(); }
};
struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET socket = INVALID_SOCKET) : value(socket) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value(std::exchange(other.value, INVALID_SOCKET)) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) { if (value != INVALID_SOCKET) closesocket(value); value = std::exchange(other.value, INVALID_SOCKET); }
        return *this;
    }
    bool nonblocking() const { u_long enabled = 1; return ioctlsocket(value, FIONBIO, &enabled) == 0; }
};
struct Io {
    const std::atomic<bool>& stop;
    ULONGLONG deadline;
    bool active() const { return !stop.load() && GetTickCount64() < deadline; }
    bool wait(SOCKET socket, short events) const {
        while (active()) {
            WSAPOLLFD poll{socket, events, 0};
            const int result = WSAPoll(&poll, 1, 50);
            if (result == SOCKET_ERROR) return false;
            if (result > 0) return (poll.revents & (events | POLLHUP)) != 0;
        }
        return false;
    }
    bool write(SOCKET socket, const void* data, size_t size) const {
        auto* bytes = static_cast<const char*>(data);
        while (size && active()) {
            const int sent = send(socket, bytes, static_cast<int>(size), 0);
            if (sent > 0) { bytes += sent; size -= static_cast<size_t>(sent); }
            else if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) { if (!wait(socket, POLLWRNORM)) return false; }
            else return false;
        }
        return size == 0;
    }
    bool read(SOCKET socket, void* data, size_t size) const {
        auto* bytes = static_cast<char*>(data);
        while (size && active()) {
            const int received = recv(socket, bytes, static_cast<int>(size), 0);
            if (received > 0) { bytes += received; size -= static_cast<size_t>(received); }
            else if (received == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) { if (!wait(socket, POLLRDNORM)) return false; }
            else return false;
        }
        return size == 0;
    }
};
inline Socket connectProxy(const Config& config, const Io& io) {
    // Asynchronous DNS makes cancellation possible even when the resolver is unavailable.
    ADDRINFOEXW hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    PADDRINFOEXW addresses = nullptr;
    OVERLAPPED operation{}; operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!operation.hEvent) return Socket{};
    HANDLE cancel = nullptr;
    const auto service = std::to_wstring(config.port);
    timeval timeout{4, 0};
    int status = GetAddrInfoExW(config.host.c_str(), service.c_str(), NS_DNS, nullptr, &hints, &addresses, &timeout, &operation, nullptr, &cancel);
    if (status == WSA_IO_PENDING) {
        while (io.active() && WaitForSingleObject(operation.hEvent, 50) == WAIT_TIMEOUT) {}
        if (WaitForSingleObject(operation.hEvent, 0) != WAIT_OBJECT_0) {
            GetAddrInfoExCancel(&cancel);
            // The OVERLAPPED and result storage must outlive cancellation completion.
            WaitForSingleObject(operation.hEvent, INFINITE);
        }
        status = GetAddrInfoExOverlappedResult(&operation);
    }
    CloseHandle(operation.hEvent);
    Socket connected;
    if (status == 0 && io.active()) {
        for (const auto* address = addresses; address && io.active(); address = address->ai_next) {
            Socket candidate(socket(address->ai_family, address->ai_socktype, address->ai_protocol));
            if (candidate.value == INVALID_SOCKET || !candidate.nonblocking()) continue;
            const int result = connect(candidate.value, address->ai_addr, static_cast<int>(address->ai_addrlen));
            if (result == SOCKET_ERROR && (WSAGetLastError() != WSAEWOULDBLOCK || !io.wait(candidate.value, POLLWRNORM))) continue;
            int error = 0, length = sizeof(error);
            if (getsockopt(candidate.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0 || error) continue;
            connected = std::move(candidate); break;
        }
    }
    if (addresses) FreeAddrInfoExW(addresses);
    return connected;
}
inline bool socksHandshake(SOCKET socket, const Config& config, const Io& io, std::wstring& error) {
    error = L"SOCKS5: ошибка протокола или тайм-аут";
    const BYTE method = config.authenticate ? 2 : 0;
    const BYTE greeting[] = {5, 1, method};
    BYTE reply[4]{};
    if (!io.write(socket, greeting, sizeof(greeting)) || !io.read(socket, reply, 2)) return false;
    if (reply[0] != 5 || reply[1] != method) { error = L"SOCKS5: сервер не принял способ авторизации"; return false; }
    if (config.authenticate) {
        auto username = utf8(config.username), password = utf8(config.password);
        Bytes auth;
        auth.value = {1, static_cast<BYTE>(username.size())};
        auth.value.insert(auth.value.end(), username.begin(), username.end());
        auth.value.push_back(static_cast<BYTE>(password.size()));
        auth.value.insert(auth.value.end(), password.begin(), password.end());
        wipe(username); wipe(password);
        if (!io.write(socket, auth.value.data(), auth.value.size()) || !io.read(socket, reply, 2)) return false;
        if (reply[0] != 1 || reply[1] != 0) { error = L"SOCKS5: неверный логин или пароль"; return false; }
    }
    // Resolve the target at the proxy, never through the local DNS resolver.
    constexpr BYTE request[] = {5, 1, 0, 3, 11, 'c', 'h', 'a', 't', 'g', 'p', 't', '.', 'c', 'o', 'm', 1, 187};
    if (!io.write(socket, request, sizeof(request)) || !io.read(socket, reply, sizeof(reply))) return false;
    if (reply[0] != 5 || reply[2] != 0) return false;
    if (reply[1] != 0) { error = L"SOCKS5: соединение отклонено (" + std::to_wstring(reply[1]) + L")"; return false; }
    size_t length = 0;
    if (reply[3] == 1) length = 4;
    else if (reply[3] == 4) length = 16;
    else if (reply[3] == 3) { BYTE count = 0; if (!io.read(socket, &count, 1) || !count) return false; length = count; }
    else return false;
    BYTE bound[257]{};
    if (!io.read(socket, bound, length + 2)) return false;
    error.clear(); return true;
}
inline void relay(SOCKET client, SOCKET upstream, const Io& io) {
    struct Direction {
        SOCKET from, to;
        std::array<char, 16384> buffer{};
        size_t begin = 0, end = 0;
        bool eof = false, closed = false;
    };
    Direction directions[] = {{client, upstream}, {upstream, client}};
    while (io.active()) {
        WSAPOLLFD polls[] = {{client, 0, 0}, {upstream, 0, 0}};
        bool done = true;
        for (int i = 0; i < 2; ++i) {
            auto& direction = directions[i];
            if (!direction.eof || direction.begin != direction.end) done = false;
            if (!direction.eof && direction.end < direction.buffer.size()) polls[i].events |= POLLRDNORM;
            if (direction.begin != direction.end) polls[1 - i].events |= POLLWRNORM;
            else if (direction.eof && !direction.closed) { shutdown(direction.to, SD_SEND); direction.closed = true; }
        }
        WSAPOLLFD active[2]{};
        int indexes[2]{}, count = 0;
        for (int i = 0; i < 2; ++i) {
            if (polls[i].events) { active[count] = polls[i]; indexes[count++] = i; }
        }
        if (done || !count || WSAPoll(active, static_cast<ULONG>(count), 50) == SOCKET_ERROR) return;
        for (int i = 0; i < count; ++i) polls[indexes[i]].revents = active[i].revents;
        for (int i = 0; i < 2; ++i) {
            auto& direction = directions[i];
            if ((polls[1 - i].revents & POLLWRNORM) && direction.begin < direction.end) {
                const int sent = send(direction.to, direction.buffer.data() + direction.begin, static_cast<int>(direction.end - direction.begin), 0);
                if (sent > 0) { direction.begin += sent; if (direction.begin == direction.end) direction.begin = direction.end = 0; }
                else if (sent != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) return;
            }
            if ((polls[i].revents & (POLLRDNORM | POLLHUP)) && !direction.eof && direction.end < direction.buffer.size()) {
                const int received = recv(direction.from, direction.buffer.data() + direction.end, static_cast<int>(direction.buffer.size() - direction.end), 0);
                if (received > 0) direction.end += received;
                else if (received == 0) direction.eof = true;
                else if (WSAGetLastError() != WSAEWOULDBLOCK) return;
            }
            if (polls[i].revents & (POLLERR | POLLNVAL)) return;
        }
    }
}
// WinHTTP retains ownership of end-to-end TLS, certificate checks and HTTP parsing.
// This single-use loopback CONNECT adapter exists only for the duration of one SOCKS5 fetch.
class SocksBridge {
    Winsock runtime;
    Socket listener;
    Config config;
    std::atomic<bool> stop{false};
    std::mutex mutex;
    std::wstring failure;
    std::thread worker;
    unsigned short port = 0;
    void fail(const std::wstring& error) { std::lock_guard<std::mutex> lock(mutex); failure = error; }
    void run() {
        const Io io{stop, GetTickCount64() + 30000};
        if (!io.wait(listener.value, POLLRDNORM)) return;
        Socket client(accept(listener.value, nullptr, nullptr));
        if (client.value == INVALID_SOCKET || !client.nonblocking()) return;
        // Only the fixed origin is permitted. The listener is bound exclusively to IPv4 loopback.
        std::string header;
        while (header.size() < 4096 && (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n") != 0)) {
            char c = 0; if (!io.read(client.value, &c, 1)) return; header += c;
        }
        if (header.size() >= 4096 || (header.find("CONNECT chatgpt.com:443 HTTP/1.1\r\n") != 0 &&
                                     header.find("CONNECT chatgpt.com:443 HTTP/1.0\r\n") != 0)) {
            fail(L"SOCKS5: неверный запрос туннеля"); return;
        }
        Socket upstream = connectProxy(config, io);
        if (upstream.value == INVALID_SOCKET) { fail(L"Не удалось подключиться к SOCKS5-прокси"); return; }
        std::wstring error;
        if (!socksHandshake(upstream.value, config, io, error)) { fail(error); return; }
        constexpr char success[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!io.write(client.value, success, sizeof(success) - 1)) return;
        relay(client.value, upstream.value, io);
    }
public:
    ~SocksBridge() { stop.store(true); if (worker.joinable()) worker.join(); }
    bool start(const Config& value) {
        config = value;
        if (!runtime.ready) return false;
        listener = Socket(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        const BOOL exclusive = TRUE;
        if (listener.value == INVALID_SOCKET || setsockopt(listener.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0) return false;
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int size = sizeof(address);
        if (bind(listener.value, reinterpret_cast<sockaddr*>(&address), size) != 0 ||
            getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) != 0 || listen(listener.value, 1) != 0 || !listener.nonblocking()) return false;
        port = ntohs(address.sin_port);
        worker = std::thread([this] { try { run(); } catch (...) { fail(L"Ошибка SOCKS5-туннеля"); } });
        return true;
    }
    std::wstring endpoint() const { return L"127.0.0.1:" + std::to_wstring(port); }
    std::wstring error() { std::lock_guard<std::mutex> lock(mutex); return failure; }
};
}
