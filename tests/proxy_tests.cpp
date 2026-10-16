#include "../src/main.cpp"
#include <iostream>
#include <stdexcept>
#include <functional>

namespace {
void require(bool valid, const char* message) { if (!valid) throw std::runtime_error(message); }
struct TestKey {
    std::wstring name = L"Software\\TrayUsage.Tests." + std::to_wstring(GetCurrentProcessId());
    ~TestKey() { RegDeleteTreeW(HKEY_CURRENT_USER, name.c_str()); }
};
void settings() {
    TestKey key;
    proxy::Config config, restored;
    std::wstring error;
    require(proxy::load(restored, error, key.name.c_str()) && restored.type == proxy::Type::system, "Missing settings must use system proxy");
    config.type = proxy::Type::socks5; config.host = L"::1"; config.port = 1080;
    config.authenticate = true; config.username = L"тест-user"; config.password = L"секрет-password";
    require(proxy::validate(config).empty(), "IPv6 / Unicode credentials rejected");
    require(proxy::endpoint(config) == L"[::1]:1080", "IPv6 endpoint malformed");
    require(proxy::save(config, error, key.name.c_str()), "DPAPI / registry save failed");
    require(proxy::load(restored, error, key.name.c_str()), "Registry reload failed");
    require(restored.type == config.type && restored.host == config.host && restored.port == config.port && restored.authenticate &&
        restored.username == config.username && restored.password == config.password, "Settings did not roundtrip");
    DWORD size = 0;
    require(RegGetValueW(HKEY_CURRENT_USER, key.name.c_str(), L"ProxyConfig", RRF_RT_REG_BINARY, nullptr, nullptr, &size) == ERROR_SUCCESS, "Expected binary registry value");
    std::vector<BYTE> bytes(size);
    require(RegGetValueW(HKEY_CURRENT_USER, key.name.c_str(), L"ProxyConfig", RRF_RT_REG_BINARY, nullptr, bytes.data(), &size) == ERROR_SUCCESS, "Cannot read encrypted settings");
    const auto* secret = reinterpret_cast<const BYTE*>(config.password.data());
    require(std::search(bytes.begin(), bytes.end(), secret, secret + config.password.size() * sizeof(wchar_t)) == bytes.end(), "Plaintext password in registry");
    bytes.back() ^= 1;
    require(RegSetKeyValueW(HKEY_CURRENT_USER, key.name.c_str(), L"ProxyConfig", REG_BINARY, bytes.data(), size) == ERROR_SUCCESS, "Cannot corrupt test value");
    require(!proxy::load(restored, error, key.name.c_str()) && !error.empty(), "Corrupt settings silently fell back to direct access");
    config.type = proxy::Type::system;
    require(proxy::save(config, error, key.name.c_str()) && proxy::load(restored, error, key.name.c_str()) && restored.type == proxy::Type::system, "Reset settings failed");
    config.type = proxy::Type::direct;
    require(proxy::save(config, error, key.name.c_str()) && proxy::load(restored, error, key.name.c_str()) && restored.type == proxy::Type::direct && restored.password.empty(), "Direct mode retained credentials");
    config.type = proxy::Type::http; config.host = L"127.0.0.1;other:80";
    require(!proxy::validate(config).empty(), "Proxy-list injection accepted");
    config.host = L"http://127.0.0.1";
    require(!proxy::validate(config).empty(), "URL accepted as host");
    config.host = L"127.0.0.1"; config.port = 0;
    require(!proxy::validate(config).empty(), "Zero port accepted");
    config.port = 8080; config.username = L"bad\r\nheader";
    require(!proxy::validate(config).empty(), "Control characters accepted in credentials");
    config.type = proxy::Type::socks5; config.username.assign(128, L'я');
    require(!proxy::validate(config).empty(), "SOCKS credentials exceed one-byte UTF-8 length");
    config.username = L"user"; config.password.clear();
    require(!proxy::validate(config).empty(), "Empty SOCKS password accepted");
}
struct Server {
    proxy::Socket listener;
    unsigned short port = 0;
    std::atomic<bool> stop{false}, passed{false};
    std::thread worker;
    explicit Server(std::function<void(SOCKET, const proxy::Io&)> handler) {
        listener = proxy::Socket(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int size = sizeof(address);
        require(listener.value != INVALID_SOCKET && bind(listener.value, reinterpret_cast<sockaddr*>(&address), size) == 0 &&
            getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) == 0 && listen(listener.value, 1) == 0 && listener.nonblocking(), "Test listener failed");
        port = ntohs(address.sin_port);
        worker = std::thread([this, handler] {
            try {
                const proxy::Io io{stop, GetTickCount64() + 10000};
                require(io.wait(listener.value, POLLRDNORM), "Test accept timeout");
                proxy::Socket peer(accept(listener.value, nullptr, nullptr));
                require(peer.value != INVALID_SOCKET && peer.nonblocking(), "Test accept failed");
                handler(peer.value, io); passed.store(true);
            } catch (const std::exception&) {}
        });
    }
    void finish() { if (worker.joinable()) worker.join(); require(passed.load(), "Mock proxy expectation failed"); }
    ~Server() { stop.store(true); if (worker.joinable()) worker.join(); }
    proxy::Config config() const { proxy::Config value; value.type = proxy::Type::socks5; value.host = L"127.0.0.1"; value.port = port; return value; }
};
void fragmented(SOCKET peer, const proxy::Io& io, const std::vector<BYTE>& bytes) {
    for (const BYTE value : bytes) require(io.write(peer, &value, 1), "Fragmented send failed");
}
void expect(SOCKET peer, const proxy::Io& io, const std::vector<BYTE>& bytes) {
    std::vector<BYTE> actual(bytes.size());
    require(io.read(peer, actual.data(), actual.size()) && actual == bytes, "Unexpected SOCKS packet");
}
void socks(bool authenticate, BYTE addressType) {
    Server server([=](SOCKET peer, const proxy::Io& io) {
        expect(peer, io, {5, 1, static_cast<BYTE>(authenticate ? 2 : 0)});
        fragmented(peer, io, {5, static_cast<BYTE>(authenticate ? 2 : 0)});
        if (authenticate) { expect(peer, io, {1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}); fragmented(peer, io, {1, 0}); }
        expect(peer, io, {5, 1, 0, 3, 11, 'c', 'h', 'a', 't', 'g', 'p', 't', '.', 'c', 'o', 'm', 1, 187});
        std::vector<BYTE> response{5, 0, 0, addressType};
        if (addressType == 3) { response.insert(response.end(), {3, 'd', 'n', 's'}); }
        else response.resize(response.size() + (addressType == 1 ? 4 : 16), 0);
        response.insert(response.end(), {0, 80}); fragmented(peer, io, response);
        std::array<char, 4096> buffer{};
        size_t count = 0;
        while (count < 512 * 1024) {
            const size_t chunk = std::min(buffer.size(), 512 * 1024 - count);
            require(io.read(peer, buffer.data(), chunk) && io.write(peer, buffer.data(), chunk), "Echo failed"); count += chunk;
        }
    });
    auto config = server.config(); config.authenticate = authenticate; config.username = L"user"; config.password = L"pass";
    proxy::SocksBridge bridge;
    require(bridge.start(config), "Bridge did not start");
    proxy::Config local; local.host = L"127.0.0.1"; local.port = static_cast<unsigned short>(std::stoi(bridge.endpoint().substr(10)));
    std::atomic<bool> stop{false}; const proxy::Io io{stop, GetTickCount64() + 10000};
    auto client = proxy::connectProxy(local, io);
    require(client.value != INVALID_SOCKET, "Cannot connect to bridge");
    constexpr char connect[] = "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n";
    require(io.write(client.value, connect, sizeof(connect) - 1), "CONNECT send failed");
    char response[39]{};
    require(io.read(client.value, response, sizeof(response)) && std::string(response, sizeof(response)) == "HTTP/1.1 200 Connection Established\r\n\r\n", "CONNECT failed");
    std::vector<char> payload(512 * 1024), received(payload.size());
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    std::atomic<bool> wrote{false};
    std::thread writer([&] { wrote.store(io.write(client.value, payload.data(), payload.size())); });
    const bool read = io.read(client.value, received.data(), received.size());
    writer.join();
    require(read && wrote.load() && payload == received, "Relay lost data / failed backpressure");
    server.finish();
}
void rejected(BYTE method, const std::vector<BYTE>& response, bool authenticate, const wchar_t* expected) {
    Server server([=](SOCKET peer, const proxy::Io& io) {
        expect(peer, io, {5, 1, static_cast<BYTE>(authenticate ? 2 : 0)});
        fragmented(peer, io, {5, method});
        if (method == (authenticate ? 2 : 0)) {
            if (authenticate) expect(peer, io, {1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'});
            else expect(peer, io, {5, 1, 0, 3, 11, 'c', 'h', 'a', 't', 'g', 'p', 't', '.', 'c', 'o', 'm', 1, 187});
            fragmented(peer, io, response);
        }
    });
    auto config = server.config(); config.authenticate = authenticate; config.username = L"user"; config.password = L"pass";
    std::atomic<bool> stop{false}; const proxy::Io io{stop, GetTickCount64() + 3000};
    auto client = proxy::connectProxy(config, io);
    std::wstring error;
    require(client.value != INVALID_SOCKET && !proxy::socksHandshake(client.value, config, io, error) && error.find(expected) != std::wstring::npos, "Invalid SOCKS response accepted / wrong error");
    server.finish();
}
void timeoutAndCancel() {
    Server server([](SOCKET peer, const proxy::Io& io) {
        expect(peer, io, {5, 1, 0});
        BYTE byte = 0; require(!io.read(peer, &byte, 1), "Expected closed peer");
    });
    auto config = server.config();
    std::atomic<bool> stop{false}; const proxy::Io io{stop, GetTickCount64() + 2000};
    {
        auto client = proxy::connectProxy(config, io);
        std::wstring error; const ULONGLONG start = GetTickCount64();
        const proxy::Io shortIo{stop, start + 150};
        require(!proxy::socksHandshake(client.value, config, shortIo, error) && GetTickCount64() - start < 1000, "Handshake timeout unbounded");
    }
    server.finish();
    const ULONGLONG start = GetTickCount64();
    { proxy::SocksBridge unused; require(unused.start(config), "Bridge start failed"); }
    require(GetTickCount64() - start < 1000, "Unused bridge shutdown blocked");
}
void httpAuthentication(bool authenticate) {
    Server server([=](SOCKET peer, const proxy::Io& io) {
        std::string request;
        while (request.size() < 4096 && request.find("\r\n\r\n") == std::string::npos) { char c; require(io.read(peer, &c, 1), "Missing CONNECT"); request += c; }
        require(request.find("CONNECT chatgpt.com:443 HTTP/1.") == 0, "WinHTTP did not use CONNECT");
        require(request.find("Bearer") == std::string::npos, "Origin token leaked into proxy CONNECT");
        if (authenticate) require(request.find("Proxy-Authorization: Basic dXNlcjpwYXNz") != std::string::npos, "Missing proxy authentication");
        constexpr char denied[] = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        require(io.write(peer, denied, sizeof(denied) - 1), "Cannot send 407");
    });
    auto config = server.config(); config.type = proxy::Type::http; config.authenticate = authenticate; config.username = L"user"; config.password = L"pass";
    const auto address = proxy::endpoint(config);
    HttpHandle session(WinHttpOpen(L"TrayUsage tests", WINHTTP_ACCESS_TYPE_NAMED_PROXY, address.c_str(), WINHTTP_NO_PROXY_BYPASS, 0));
    require(session.value && WinHttpSetTimeouts(session.value, 1000, 1000, 1000, 1000), "WinHTTP session failed");
    HttpHandle connection(WinHttpConnect(session.value, L"chatgpt.com", 443, 0));
    HttpHandle request(WinHttpOpenRequest(connection.value, L"GET", L"/", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    std::wstring error; DWORD status = 0;
    require(request.value && !sendRequest(request.value, L"Authorization: Bearer dummy-test-token\r\n", config, status, error), "407 unexpectedly succeeded");
    require(!error.empty(), "Missing proxy error"); server.finish();
}
void tlsProbe(const char* type, const char* port, bool trustFixture, bool authenticate) {
    proxy::Config config;
    config.type = std::string(type) == "socks5" ? proxy::Type::socks5 : proxy::Type::http;
    config.host = L"127.0.0.1"; config.port = static_cast<unsigned short>(std::stoi(port));
    config.authenticate = authenticate; config.username = L"user"; config.password = L"pass";
    std::unique_ptr<proxy::SocksBridge> bridge;
    std::wstring address = proxy::endpoint(config);
    if (config.type == proxy::Type::socks5) {
        bridge = std::make_unique<proxy::SocksBridge>(); require(bridge->start(config), "TLS bridge did not start"); address = bridge->endpoint();
    }
    HttpHandle session(WinHttpOpen(L"TrayUsage TLS tests", WINHTTP_ACCESS_TYPE_NAMED_PROXY, address.c_str(), WINHTTP_NO_PROXY_BYPASS, 0));
    require(session.value && WinHttpSetTimeouts(session.value, 2000, 2000, 2000, 2000), "TLS session failed");
    HttpHandle connection(WinHttpConnect(session.value, L"chatgpt.com", 443, 0));
    HttpHandle request(WinHttpOpenRequest(connection.value, L"GET", L"/backend-api/wham/usage", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    require(request.value != nullptr, "TLS request failed");
    // Test executable only: accept the temporary, untrusted localhost fixture certificate.
    // A separate probe below uses normal verification and must reject that same certificate.
    if (trustFixture) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        require(WinHttpSetOption(request.value, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags)) != FALSE, "Test fixture trust failed");
    }
    DWORD status = 0; std::wstring error;
    const bool sent = sendRequest(request.value, L"Authorization: Bearer dummy-test-token\r\nChatGPT-Account-Id: dummy-account\r\n", config, status, error);
    if (!trustFixture) {
        require(!sent && error.find(std::to_wstring(ERROR_WINHTTP_SECURE_FAILURE)) != std::wstring::npos, "Untrusted TLS certificate accepted / wrong error");
        std::cout << "Untrusted TLS certificate rejected\n"; return;
    }
    require(sent && status == 200, "HTTPS via proxy failed");
    std::string body; char buffer[128]; DWORD count = 0;
    do { require(WinHttpReadData(request.value, buffer, sizeof(buffer), &count) != FALSE, "TLS response read failed"); body.append(buffer, count); } while (count);
    const auto snapshot = usage::parse(body);
    require(snapshot.shortWindow && snapshot.shortWindow->remaining() == 59 && snapshot.weeklyWindow && snapshot.weeklyWindow->remaining() == 83, "HTTPS response changed in transit");
    std::cout << "HTTPS via " << type << " passed\n";
}
}
int main(int argc, char** argv) {
    try {
        proxy::Winsock runtime; require(runtime.ready, "WSAStartup failed");
        if (argc == 6 && std::string(argv[1]) == "--tls") { tlsProbe(argv[2], argv[3], std::string(argv[4]) == "trust", std::string(argv[5]) == "auth"); return 0; }
        settings();
        for (const BYTE address : {static_cast<BYTE>(1), static_cast<BYTE>(3), static_cast<BYTE>(4)}) { socks(false, address); socks(true, address); }
        rejected(255, {}, false, L"авторизации");
        rejected(0, {}, true, L"авторизации");
        rejected(2, {1, 1}, true, L"логин");
        rejected(0, {5, 5, 0, 1}, false, L"отклонено");
        rejected(0, {4, 0, 0, 1}, false, L"протокола");
        rejected(0, {5, 0, 1, 1}, false, L"протокола");
        rejected(0, {5, 0, 0, 9}, false, L"протокола");
        timeoutAndCancel(); httpAuthentication(false); httpAuthentication(true);
        std::cout << "Proxy tests passed: DPAPI/registry, validation, HTTP CONNECT/auth, SOCKS5 auth/replies, fragmented I/O, 512 KiB relay, timeouts/cancellation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
