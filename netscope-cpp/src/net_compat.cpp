#include "net_compat.h"

#include <array>
#include <cstring>
#include <mutex>

namespace netscope {

void netInit() {
#ifdef _WIN32
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data{};
        // Failure here is fatal to every network operation, but throwing from a
        // library initializer would be worse than letting the individual calls
        // report their own errors.
        (void)WSAStartup(MAKEWORD(2, 2), &data);
    });
#endif
}

std::string parseIPLiteral(std::string_view s) {
    netInit();
    const std::string text(s);

    in_addr v4{};
    if (::inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        std::array<char, INET_ADDRSTRLEN> buf{};
        if (::inet_ntop(AF_INET, &v4, buf.data(), buf.size()) != nullptr) {
            return std::string(buf.data());
        }
        return "";
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        std::array<char, INET6_ADDRSTRLEN> buf{};
        if (::inet_ntop(AF_INET6, &v6, buf.data(), buf.size()) != nullptr) {
            return std::string(buf.data());
        }
        return "";
    }
    return "";
}

bool isPrivateOrReserved(std::string_view ip) {
    netInit();
    const std::string text(ip);

    in_addr v4{};
    if (::inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        std::array<unsigned char, 4> b{};
        std::memcpy(b.data(), &v4, 4);
        if (b[0] == 10) return true;                                   // 10/8
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;      // 172.16/12
        if (b[0] == 192 && b[1] == 168) return true;                   // 192.168/16
        if (b[0] == 127) return true;                                  // loopback
        if (b[0] == 169 && b[1] == 254) return true;                   // link-local
        if (b[0] >= 224) return true;                                  // multicast / reserved
        if (b[0] == 0) return true;                                    // unspecified
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;     // RFC 6598 CGNAT
        return false;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        std::array<unsigned char, 16> b{};
        std::memcpy(b.data(), &v6, 16);
        bool allZeroButLast = true;
        for (int i = 0; i < 15; ++i) {
            if (b[static_cast<std::size_t>(i)] != 0) {
                allZeroButLast = false;
                break;
            }
        }
        if (allZeroButLast && (b[15] == 1 || b[15] == 0)) return true;  // ::1 and ::
        if ((b[0] & 0xfe) == 0xfc) return true;                        // fc00::/7 unique local
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true;        // fe80::/10 link-local
        if (b[0] == 0xff) return true;                                 // ff00::/8 multicast
        return false;
    }

    // Not an address at all: treat as reserved so we never send garbage to a
    // public resolver.
    return true;
}

}  // namespace netscope
