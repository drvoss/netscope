#include "sysinfo.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>

#include "health.h"
#include "net_compat.h"

#ifndef _WIN32
#include <cstdio>
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace netscope {
namespace {

// Asks the kernel which local address would be used to reach the target. A UDP
// "connect" sends no packets; it only performs a route lookup.
std::string sourceAddressFor(const std::string& targetIp) {
    if (targetIp.empty()) return "";
    netInit();

    const bool v6 = targetIp.find(':') != std::string::npos;
    const int domain = v6 ? AF_INET6 : AF_INET;

#ifdef _WIN32
    SOCKET fd = ::socket(domain, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCKET) return "";
#else
    int fd = ::socket(domain, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return "";
#endif

    sockaddr_storage dst{};
    socklen_t dstLen = 0;
    if (v6) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&dst);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(80);
        ::inet_pton(AF_INET6, targetIp.c_str(), &a->sin6_addr);
        dstLen = sizeof(sockaddr_in6);
    } else {
        auto* a = reinterpret_cast<sockaddr_in*>(&dst);
        a->sin_family = AF_INET;
        a->sin_port = htons(80);
        ::inet_pton(AF_INET, targetIp.c_str(), &a->sin_addr);
        dstLen = sizeof(sockaddr_in);
    }

    std::string out;
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&dst), dstLen) == 0) {
        sockaddr_storage local{};
        socklen_t localLen = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &localLen) == 0) {
            std::array<char, INET6_ADDRSTRLEN> buf{};
            if (local.ss_family == AF_INET) {
                const auto* a = reinterpret_cast<const sockaddr_in*>(&local);
                if (::inet_ntop(AF_INET, &a->sin_addr, buf.data(), buf.size())) out = buf.data();
            } else {
                const auto* a = reinterpret_cast<const sockaddr_in6*>(&local);
                if (::inet_ntop(AF_INET6, &a->sin6_addr, buf.data(), buf.size())) out = buf.data();
            }
        }
    }

#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
    return out;
}

std::string sockaddrText(const sockaddr* sa) {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    if (sa == nullptr) return "";
    if (sa->sa_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(sa);
        if (::inet_ntop(AF_INET, &a->sin_addr, buf.data(), buf.size())) return buf.data();
    } else if (sa->sa_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(sa);
        if (::inet_ntop(AF_INET6, &a->sin6_addr, buf.data(), buf.size())) return buf.data();
    }
    return "";
}

}  // namespace

#ifdef _WIN32

namespace {

// FriendlyName is a wide string; the model stores UTF-8 everywhere.
std::string narrowFriendlyName(const wchar_t* name) {
    if (name == nullptr) return "";
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
    if (need <= 1) return "";
    std::string out(static_cast<std::size_t>(need - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, name, -1, out.data(), need, nullptr, nullptr);
    return out;
}

// Wraps GetAdaptersAddresses, growing the buffer as the API asks.
std::vector<unsigned char> adaptersBuffer() {
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    for (int attempt = 0; attempt < 4; ++attempt) {
        // FriendlyName is deliberately NOT skipped: AdapterName is the adapter GUID,
        // and reporting "{8256675B-...}" where the Go build reports "Ethernet" would
        // be an observable parity difference in the LOCAL IF panel.
        const ULONG rc = ::GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
        if (rc == ERROR_SUCCESS) return buf;
        if (rc != ERROR_BUFFER_OVERFLOW) return {};
        buf.assign(size, 0);
    }
    return {};
}

}  // namespace

// Uses the IP Helper APIs rather than parsing `route print` / `ipconfig /all`,
// whose column headers and labels are localized (plan §5.2).
RouteInfo platformRouteInfo() {
    RouteInfo info;
    netInit();

    MIB_IPFORWARD_TABLE2* table = nullptr;
    if (::GetIpForwardTable2(AF_UNSPEC, &table) != NO_ERROR || table == nullptr) {
        info.note = "cannot read the routing table";
        return info;
    }

    ULONG bestMetric = ULONG_MAX;
    std::string bestGateway;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& row = table->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0) continue;  // default route only
        const std::string gw = sockaddrText(reinterpret_cast<const sockaddr*>(&row.NextHop));
        if (gw.empty() || gw == "0.0.0.0" || gw == "::") continue;
        if (row.Metric < bestMetric) {
            bestMetric = row.Metric;
            bestGateway = gw;
        }
    }
    ::FreeMibTable(table);

    if (bestGateway.empty()) {
        info.note = "no default route found";
        return info;
    }
    info.gateway = bestGateway;
    info.defaultRoute = (bestGateway.find(':') == std::string::npos ? "0.0.0.0/0 via "
                                                                   : "::/0 via ") +
                        bestGateway;
    return info;
}

DnsInfo platformDnsServers() {
    DnsInfo info;
    const auto buf = adaptersBuffer();
    if (buf.empty()) {
        info.note = "cannot enumerate network adapters";
        return info;
    }

    const auto* head = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buf.data());
    for (const IP_ADAPTER_ADDRESSES* a = head; a != nullptr; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (const IP_ADAPTER_DNS_SERVER_ADDRESS* d = a->FirstDnsServerAddress; d != nullptr;
             d = d->Next) {
            const std::string ip = sockaddrText(d->Address.lpSockaddr);
            if (ip.empty()) continue;
            // Skip the well-known IPv6 site-local DNS placeholders Windows lists.
            if (ip.rfind("fec0:", 0) == 0) continue;
            if (std::find(info.servers.begin(), info.servers.end(), ip) == info.servers.end()) {
                info.servers.push_back(ip);
            }
        }
    }
    std::sort(info.servers.begin(), info.servers.end());
    if (info.servers.empty()) info.note = "no DNS servers configured";
    return info;
}

namespace {

// Finds the adapter owning src and returns its name and the address in CIDR form.
void interfaceForWindows(const std::string& src, std::string& name, std::string& cidr) {
    cidr = src;
    const auto buf = adaptersBuffer();
    if (buf.empty()) return;

    const auto* head = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buf.data());
    for (const IP_ADAPTER_ADDRESSES* a = head; a != nullptr; a = a->Next) {
        for (const IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u != nullptr;
             u = u->Next) {
            if (sockaddrText(u->Address.lpSockaddr) != src) continue;
            name = narrowFriendlyName(a->FriendlyName);
            cidr = src + "/" + std::to_string(u->OnLinkPrefixLength);
            return;
        }
    }
}

}  // namespace

#else  // POSIX

// iproute2 first, then a BSD/macOS `netstat -rn` fallback. codex correctly noted
// that "POSIX" is not one platform; when neither tool exists the panel says so
// instead of showing a blank gateway (cross-review R1-4).
namespace {

bool runCapture(const std::string& cmd, std::string& out) {
    out.clear();
    FILE* pipe = ::popen(cmd.c_str(), "r");
    if (pipe == nullptr) return false;
    std::array<char, 4096> buf{};
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) out += buf.data();
    ::pclose(pipe);
    return true;
}

std::vector<std::string> fields(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream is(s);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

}  // namespace

RouteInfo platformRouteInfo() {
    RouteInfo info;

    std::string out;
    if (runCapture("LC_ALL=C ip -4 route show default 2>/dev/null", out) && !out.empty()) {
        const auto f = fields(out);
        for (std::size_t i = 0; i + 1 < f.size(); ++i) {
            if (f[i] == "via" && !parseIPLiteral(f[i + 1]).empty()) {
                info.gateway = f[i + 1];
                info.defaultRoute = "default via " + info.gateway;
                return info;
            }
        }
    }
    if (runCapture("LC_ALL=C netstat -rn 2>/dev/null", out) && !out.empty()) {
        std::istringstream is(out);
        std::string line;
        while (std::getline(is, line)) {
            const auto f = fields(line);
            if (f.size() < 2) continue;
            if (f[0] != "default" && f[0] != "0.0.0.0") continue;
            if (parseIPLiteral(f[1]).empty()) continue;
            info.gateway = f[1];
            info.defaultRoute = "default via " + info.gateway;
            return info;
        }
    }
    info.note = "no route tool available (tried ip, netstat)";
    return info;
}

// Reads /etc/resolv.conf. This misses systemd-resolved / NetworkManager / VPN
// split-DNS detail, which codex flagged; the loopback stub is reported honestly
// rather than pretended to be the real upstream resolver.
DnsInfo platformDnsServers() {
    DnsInfo info;
    std::ifstream in("/etc/resolv.conf");
    if (!in) {
        info.note = "cannot read /etc/resolv.conf";
        return info;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream is(line);
        std::string key;
        std::string value;
        if (!(is >> key >> value)) continue;
        if (key != "nameserver") continue;
        if (parseIPLiteral(value).empty()) continue;
        if (std::find(info.servers.begin(), info.servers.end(), value) == info.servers.end()) {
            info.servers.push_back(value);
        }
    }
    std::sort(info.servers.begin(), info.servers.end());
    if (info.servers.empty()) {
        info.note = "no nameserver lines in /etc/resolv.conf";
    } else if (info.servers.size() == 1 && info.servers.front().rfind("127.", 0) == 0) {
        info.note = "resolv.conf points at a local stub resolver; upstream servers not visible";
    }
    return info;
}

namespace {

void interfaceForPosix(const std::string& src, std::string& name, std::string& cidr) {
    cidr = src;
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0 || list == nullptr) return;

    for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr) continue;
        if (sockaddrText(a->ifa_addr) != src) continue;
        name = a->ifa_name != nullptr ? a->ifa_name : "";
        int prefix = 0;
        if (a->ifa_netmask != nullptr) {
            if (a->ifa_netmask->sa_family == AF_INET) {
                const auto* m = reinterpret_cast<const sockaddr_in*>(a->ifa_netmask);
                std::uint32_t mask = ntohl(m->sin_addr.s_addr);
                while (mask & 0x80000000u) {
                    ++prefix;
                    mask <<= 1;
                }
            } else if (a->ifa_netmask->sa_family == AF_INET6) {
                const auto* m = reinterpret_cast<const sockaddr_in6*>(a->ifa_netmask);
                const auto* bytes = reinterpret_cast<const unsigned char*>(&m->sin6_addr);
                for (int i = 0; i < 16; ++i) {
                    unsigned char b = bytes[i];
                    while (b & 0x80) {
                        ++prefix;
                        b = static_cast<unsigned char>(b << 1);
                    }
                }
            }
        }
        cidr = src + "/" + std::to_string(prefix);
        break;
    }
    ::freeifaddrs(list);
}

}  // namespace

#endif

LocalInfo gatherSysinfo(const std::string& targetIp, bool wantPublicIp) {
    LocalInfo info;

    const std::string src = sourceAddressFor(targetIp);
    if (!src.empty()) {
#ifdef _WIN32
        interfaceForWindows(src, info.interfaceName, info.address);
#else
        interfaceForPosix(src, info.interfaceName, info.address);
#endif
    }

    const RouteInfo route = platformRouteInfo();
    info.gateway = route.gateway;
    info.defaultRoute = route.defaultRoute;
    if (!route.note.empty()) info.note = route.note;

    const DnsInfo dns = platformDnsServers();
    info.dnsServers = dns.servers;
    if (!dns.note.empty()) {
        if (!info.note.empty()) info.note += "; ";
        info.note += dns.note;
    }

    if (wantPublicIp) info.publicIp = fetchPublicIp();

    return info;
}

}  // namespace netscope
