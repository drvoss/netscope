#include "health.h"

#include <chrono>
#include <string>
#include <system_error>

#include <asio.hpp>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#endif

namespace netscope {
namespace {

// TCP connect with a deadline, using Asio.
//
// This is the plan's §5.2 "Asio 비동기" layer: the connect and its timeout are two
// concurrent asynchronous operations on one io_context, rather than a blocking
// connect wrapped in a thread.
bool tcpConnect(const std::string& ip, int port, std::chrono::milliseconds timeout,
                std::string& note) {
    try {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        asio::steady_timer timer(io);

        asio::error_code connectResult = asio::error::would_block;
        bool timedOut = false;

        asio::ip::tcp::endpoint endpoint(asio::ip::make_address(ip),
                                         static_cast<unsigned short>(port));

        socket.async_connect(endpoint, [&](const asio::error_code& ec) {
            connectResult = ec;
            timer.cancel();
        });

        timer.expires_after(timeout);
        timer.async_wait([&](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) return;
            timedOut = true;
            socket.close();
        });

        io.run();

        if (timedOut) {
            note = "timeout";
            return false;
        }
        if (connectResult) {
            note = "refused";
            return false;
        }
        note = "open";
        socket.close();
        return true;
    } catch (const std::exception&) {
        note = "error";
        return false;
    }
}

#ifdef _WIN32

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int need = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<std::size_t>(need > 0 ? need - 1 : 0), L'\0');
    if (need > 1) {
        ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), need);
    }
    return out;
}

// One HTTP request via WinHTTP.
//
// WinHTTP rather than Asio+OpenSSL on Windows: it speaks TLS using the system
// trust store with no third-party dependency, so an https:// target works out of
// the box. `body` is filled only when wanted (the public-IP reflector needs it).
bool winHttpRequest(const std::string& host, int port, const std::string& path,
                    const std::string& method, bool secure, int& status, std::string* body,
                    std::string& note) {
    HINTERNET session = ::WinHttpOpen(L"netscope/0.3", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        note = "WinHttpOpen failed";
        return false;
    }
    ::WinHttpSetTimeouts(session, 3000, 3000, 5000, 5000);

    HINTERNET connection =
        ::WinHttpConnect(session, widen(host).c_str(), static_cast<INTERNET_PORT>(port), 0);
    if (connection == nullptr) {
        ::WinHttpCloseHandle(session);
        note = "connect failed";
        return false;
    }

    const DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0u;
    HINTERNET request = ::WinHttpOpenRequest(connection, widen(method).c_str(), widen(path).c_str(),
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (request == nullptr) {
        ::WinHttpCloseHandle(connection);
        ::WinHttpCloseHandle(session);
        note = "request setup failed";
        return false;
    }

    // Report the first hop's status rather than following redirects, so the number
    // in the bar corresponds to the host we measured.
    DWORD disableRedirects = WINHTTP_DISABLE_REDIRECTS;
    ::WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirects,
                       sizeof(disableRedirects));

    bool ok = ::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA,
                                   0, 0, 0) != FALSE;
    if (ok) ok = ::WinHttpReceiveResponse(request, nullptr) != FALSE;

    if (!ok) {
        const DWORD err = ::GetLastError();
        note = (err == ERROR_WINHTTP_TIMEOUT) ? "timeout" : "no response";
        ::WinHttpCloseHandle(request);
        ::WinHttpCloseHandle(connection);
        ::WinHttpCloseHandle(session);
        return false;
    }

    DWORD code = 0;
    DWORD size = sizeof(code);
    if (::WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &code, &size,
                              WINHTTP_NO_HEADER_INDEX) == FALSE) {
        note = "no status";
        ::WinHttpCloseHandle(request);
        ::WinHttpCloseHandle(connection);
        ::WinHttpCloseHandle(session);
        return false;
    }
    status = static_cast<int>(code);

    if (body != nullptr) {
        body->clear();
        for (;;) {
            DWORD available = 0;
            if (::WinHttpQueryDataAvailable(request, &available) == FALSE || available == 0) break;
            if (body->size() > 4096) break;
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (::WinHttpReadData(request, chunk.data(), available, &read) == FALSE) break;
            body->append(chunk, 0, read);
        }
    }

    ::WinHttpCloseHandle(request);
    ::WinHttpCloseHandle(connection);
    ::WinHttpCloseHandle(session);
    return true;
}

#endif  // _WIN32

}  // namespace

Health checkHealth(const std::string& host, const std::string& ip, int port, Dur now) {
    Health h;
    h.tcpPort = port;
    h.checkedAt = now;

    h.tcpOpen = tcpConnect(ip, port, std::chrono::milliseconds(3000), h.tcpNote);

    const bool secure = (port == 443 || port == 8443);

#ifdef _WIN32
    // HEAD first, then a GET fallback: a fair number of servers answer HEAD with
    // 405 while serving GET normally.
    int status = 0;
    std::string note;
    if (winHttpRequest(host, port, "/", "HEAD", secure, status, nullptr, note) && status != 405) {
        h.httpStatus = status;
        h.httpNote = "HEAD";
    } else if (winHttpRequest(host, port, "/", "GET", secure, status, nullptr, note)) {
        h.httpStatus = status;
        h.httpNote = "GET";
    } else {
        h.httpNote = note.empty() ? "no response" : note;
    }
    if (h.httpStatus > 0) {
        // Measure the whole request so the number is comparable with the Go build's
        // application-level latency.
        const auto start = std::chrono::steady_clock::now();
        int again = 0;
        std::string ignored;
        (void)winHttpRequest(host, port, "/", h.httpNote == "GET" ? "GET" : "HEAD", secure, again,
                             nullptr, ignored);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        h.httpLatencyMs = std::chrono::duration<double, std::milli>(elapsed).count();
    }
#else
    // POSIX: plain HTTP over Asio. A TLS check needs an OpenSSL-backed
    // asio::ssl::stream; when this build has no TLS backend the bar says so rather
    // than reporting a misleading zero (spec §6.5 known limitations).
    if (secure) {
        h.httpNote = "TLS check not built on this platform";
    } else {
        try {
            const auto start = std::chrono::steady_clock::now();
            asio::io_context io;
            asio::ip::tcp::socket socket(io);
            socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address(ip),
                                                   static_cast<unsigned short>(port)));
            const std::string req = "HEAD / HTTP/1.1\r\nHost: " + host +
                                    "\r\nUser-Agent: netscope/0.3\r\nConnection: close\r\n\r\n";
            asio::write(socket, asio::buffer(req));

            asio::streambuf buf;
            asio::error_code ec;
            asio::read_until(socket, buf, "\r\n", ec);
            std::istream is(&buf);
            std::string version;
            int code = 0;
            is >> version >> code;
            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (code > 0) {
                h.httpStatus = code;
                h.httpNote = "HEAD";
                h.httpLatencyMs = std::chrono::duration<double, std::milli>(elapsed).count();
            } else {
                h.httpNote = "no status";
            }
            socket.close(ec);
        } catch (const std::exception&) {
            h.httpNote = "no response";
        }
    }
    (void)secure;
#endif

    return h;
}

std::string fetchPublicIp() {
#ifdef _WIN32
    int status = 0;
    std::string body;
    std::string note;
    if (!winHttpRequest("api.ipify.org", 443, "/", "GET", true, status, &body, note)) return "";
    if (status < 200 || status >= 300) return "";
    // Trim whitespace and validate, so a captive portal's HTML never lands in the
    // header as if it were an address.
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' ')) {
        body.pop_back();
    }
    if (body.size() > 45) return "";
    try {
        (void)asio::ip::make_address(body);
    } catch (const std::exception&) {
        return "";
    }
    return body;
#else
    // Plain HTTP reflector so this works without a TLS backend. The response is
    // validated as an IP literal before it is displayed.
    try {
        asio::io_context io;
        asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("api.ipify.org", "80");
        asio::ip::tcp::socket socket(io);
        asio::connect(socket, endpoints);
        const std::string req =
            "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: netscope/0.3\r\n"
            "Connection: close\r\n\r\n";
        asio::write(socket, asio::buffer(req));

        asio::error_code ec;
        std::string response;
        std::array<char, 512> chunk{};
        for (;;) {
            const std::size_t n = socket.read_some(asio::buffer(chunk), ec);
            if (ec) break;
            response.append(chunk.data(), n);
            if (response.size() > 4096) break;
        }
        const auto split = response.find("\r\n\r\n");
        if (split == std::string::npos) return "";
        std::string body = response.substr(split + 4);
        while (!body.empty() &&
               (body.back() == '\n' || body.back() == '\r' || body.back() == ' ')) {
            body.pop_back();
        }
        if (body.empty() || body.size() > 45) return "";
        (void)asio::ip::make_address(body);
        return body;
    } catch (const std::exception&) {
        return "";
    }
#endif
}

}  // namespace netscope
