#include "resolve.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "net_compat.h"

#ifdef _WIN32
#include <windns.h>
#else
#include <arpa/nameser.h>
#include <resolv.h>
#endif

namespace netscope {
namespace {

std::string trimSpaces(std::string s) {
    const char* ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::vector<std::string> splitPipe(const std::string& s) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto p = s.find('|', start);
        if (p == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

}  // namespace

bool resolveTarget(const std::string& input, Target& out, std::string& err) {
    netInit();
    out = Target{};
    out.input = input;

    if (std::string lit = parseIPLiteral(input); !lit.empty()) {
        out.ip = lit;
        out.family = (lit.find(':') != std::string::npos) ? Family::IP6 : Family::IP4;
        return true;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(input.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) {
        err = "name resolution failed";
        return false;
    }

    std::string v4;
    std::string v6;
    for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
        std::array<char, INET6_ADDRSTRLEN> buf{};
        if (a->ai_family == AF_INET && v4.empty()) {
            const auto* sa = reinterpret_cast<const sockaddr_in*>(a->ai_addr);
            if (::inet_ntop(AF_INET, &sa->sin_addr, buf.data(), buf.size())) v4 = buf.data();
        } else if (a->ai_family == AF_INET6 && v6.empty()) {
            const auto* sa = reinterpret_cast<const sockaddr_in6*>(a->ai_addr);
            if (::inet_ntop(AF_INET6, &sa->sin6_addr, buf.data(), buf.size())) v6 = buf.data();
        }
    }
    ::freeaddrinfo(res);

    // IPv4 preferred so the default path matches ping/tracert expectations.
    if (!v4.empty()) {
        out.ip = v4;
        out.family = Family::IP4;
        return true;
    }
    if (!v6.empty()) {
        out.ip = v6;
        out.family = Family::IP6;
        return true;
    }
    err = "no usable address for " + input;
    return false;
}

std::string cymruOriginName(const std::string& ip) {
    netInit();

    in_addr v4{};
    if (::inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        std::array<unsigned char, 4> b{};
        std::memcpy(b.data(), &v4, 4);
        return std::to_string(b[3]) + "." + std::to_string(b[2]) + "." + std::to_string(b[1]) +
               "." + std::to_string(b[0]) + ".origin.asn.cymru.com";
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        std::array<unsigned char, 16> b{};
        std::memcpy(b.data(), &v6, 16);
        static constexpr char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(80);
        for (int i = 15; i >= 0; --i) {
            const unsigned char byte = b[static_cast<std::size_t>(i)];
            out += hex[byte & 0xf];
            out += '.';
            out += hex[byte >> 4];
            out += '.';
        }
        out += "origin6.asn.cymru.com";
        return out;
    }
    return "";
}

std::string cymruFirstField(const std::string& txt) {
    const auto parts = splitPipe(txt);
    if (parts.empty()) return "";
    const std::string f = trimSpaces(parts.front());
    if (f.empty()) return "";
    for (char c : f) {
        if (c < '0' || c > '9') return "";
    }
    return f;
}

std::string cymruOrgField(const std::string& txt) {
    const auto parts = splitPipe(txt);
    if (parts.size() < 5) return "";
    return trimSpaces(parts.back());
}

#ifdef _WIN32

std::vector<std::string> lookupTXT(const std::string& name) {
    std::vector<std::string> out;
    PDNS_RECORD rec = nullptr;
    const DNS_STATUS st =
        ::DnsQuery_UTF8(name.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, nullptr, &rec, nullptr);
    if (st != 0 || rec == nullptr) return out;

    for (PDNS_RECORD p = rec; p != nullptr; p = p->pNext) {
        if (p->wType != DNS_TYPE_TEXT) continue;
        std::string joined;
        for (DWORD i = 0; i < p->Data.TXT.dwStringCount; ++i) {
            if (p->Data.TXT.pStringArray[i] != nullptr) joined += p->Data.TXT.pStringArray[i];
        }
        if (!joined.empty()) out.push_back(joined);
    }
    ::DnsRecordListFree(rec, DnsFreeRecordList);
    return out;
}

#else

std::vector<std::string> lookupTXT(const std::string& name) {
    std::vector<std::string> out;
    std::array<unsigned char, 4096> answer{};

    const int len = ::res_query(name.c_str(), ns_c_in, ns_t_txt, answer.data(),
                                static_cast<int>(answer.size()));
    if (len <= 0) return out;

    ns_msg handle{};
    if (::ns_initparse(answer.data(), len, &handle) < 0) return out;

    // ns_msg_count / ns_rr_type / ns_rr_rdata / ns_rr_rdlen are MACROS in
    // <arpa/nameser.h>, not functions, so they must not be written with a leading
    // "::". Only ns_initparse and ns_parserr are real functions. Caught by the
    // Keep this branch warning-clean in the Linux CI build.
    const int count = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < count; ++i) {
        ns_rr rr{};
        if (::ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_txt) continue;

        const unsigned char* rdata = ns_rr_rdata(rr);
        const std::size_t rdlen = ns_rr_rdlen(rr);
        std::string joined;
        std::size_t pos = 0;
        while (pos < rdlen) {
            const std::size_t chunk = rdata[pos];
            ++pos;
            if (pos + chunk > rdlen) break;
            joined.append(reinterpret_cast<const char*>(rdata + pos), chunk);
            pos += chunk;
        }
        if (!joined.empty()) out.push_back(joined);
    }
    return out;
}

#endif

std::optional<std::string> EnrichCache::get(std::map<std::string, Entry>& m, const std::string& key,
                                            std::chrono::steady_clock::duration ttl) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = m.find(key);
    if (it == m.end()) return std::nullopt;
    if (std::chrono::steady_clock::now() - it->second.at > ttl) return std::nullopt;
    return it->second.value;
}

void EnrichCache::put(std::map<std::string, Entry>& m, const std::string& key,
                      const std::string& value) {
    std::lock_guard<std::mutex> lk(mu_);
    m[key] = Entry{value, std::chrono::steady_clock::now()};
}

void EnrichCache::invalidate(const std::string& ip, bool dns, bool asn) {
    std::lock_guard<std::mutex> lk(mu_);
    if (dns) rdns_.erase(ip);
    if (asn) {
        asn_.erase(ip);
        org_.erase(ip);
    }
}

std::string EnrichCache::reverseDNS(const std::string& ip) {
    if (auto cached = get(rdns_, ip, kRdnsTTL)) return *cached;
    netInit();

    sockaddr_storage ss{};
    socklen_t len = 0;

    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_addr = v4;
        len = sizeof(sockaddr_in);
    } else if (::inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_addr = v6;
        len = sizeof(sockaddr_in6);
    } else {
        return "-";
    }

    std::array<char, NI_MAXHOST> host{};
    const int rc = ::getnameinfo(reinterpret_cast<const sockaddr*>(&ss), len, host.data(),
                                 static_cast<unsigned>(host.size()), nullptr, 0, NI_NAMEREQD);
    std::string value = "-";
    if (rc == 0 && host[0] != '\0') {
        value = host.data();
        if (!value.empty() && value.back() == '.') value.pop_back();
    }
    put(rdns_, ip, value);
    return value;
}

void EnrichCache::asnLookup(const std::string& ip, std::string& asn, std::string& org) {
    if (auto cachedAsn = get(asn_, ip, kAsnTTL)) {
        asn = *cachedAsn;
        org = get(org_, ip, kAsnTTL).value_or("-");
        return;
    }

    const std::string name = cymruOriginName(ip);
    if (name.empty()) {
        asn = "-";
        org = "-";
        return;
    }

    const auto txts = lookupTXT(name);
    if (txts.empty()) {
        put(asn_, ip, "-");
        put(org_, ip, "-");
        asn = "-";
        org = "-";
        return;
    }

    const std::string number = cymruFirstField(txts.front());
    if (number.empty()) {
        put(asn_, ip, "-");
        put(org_, ip, "-");
        asn = "-";
        org = "-";
        return;
    }

    asn = "AS" + number;
    put(asn_, ip, asn);

    org = "-";
    const auto desc = lookupTXT("AS" + number + ".asn.cymru.com");
    if (!desc.empty()) {
        const std::string parsed = cymruOrgField(desc.front());
        if (!parsed.empty()) org = parsed;
    }
    put(org_, ip, org);
}

EnrichResult EnrichCache::lookup(const std::string& ip) {
    EnrichResult res;
    res.ip = ip;
    if (parseIPLiteral(ip).empty()) return res;

    res.rdns = reverseDNS(ip);
    if (res.rdns.empty()) res.rdns = "-";

    if (isPrivateOrReserved(ip)) {
        // Never send internal topology to a public service (spec §7).
        res.asn = "-";
        res.org = "-";
        return res;
    }
    asnLookup(ip, res.asn, res.org);
    return res;
}

// Cached for kDnsTTL so the periodic refresh does not re-query every cycle
// (spec §7); a failed lookup is not cached, so a transient DNS outage recovers on
// the next refresh instead of being remembered for five minutes.
Records EnrichCache::lookupRecords(const std::string& host) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = records_.find(host);
        if (it != records_.end() && std::chrono::steady_clock::now() - it->second.at <= kDnsTTL) {
            return it->second.value;
        }
    }

    Records rec;
    netInit();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
        rec.note = "lookup failed";
        return rec;
    }
    for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
        std::array<char, INET6_ADDRSTRLEN> buf{};
        if (a->ai_family == AF_INET) {
            const auto* sa = reinterpret_cast<const sockaddr_in*>(a->ai_addr);
            if (::inet_ntop(AF_INET, &sa->sin_addr, buf.data(), buf.size())) {
                std::string v = buf.data();
                if (std::find(rec.a.begin(), rec.a.end(), v) == rec.a.end()) rec.a.push_back(v);
            }
        } else if (a->ai_family == AF_INET6) {
            const auto* sa = reinterpret_cast<const sockaddr_in6*>(a->ai_addr);
            if (::inet_ntop(AF_INET6, &sa->sin6_addr, buf.data(), buf.size())) {
                std::string v = buf.data();
                if (std::find(rec.aaaa.begin(), rec.aaaa.end(), v) == rec.aaaa.end()) {
                    rec.aaaa.push_back(v);
                }
            }
        }
    }
    ::freeaddrinfo(res);

    if (!rec.a.empty()) rec.ptr = reverseDNS(rec.a.front());

    {
        std::lock_guard<std::mutex> lk(mu_);
        records_[host] = RecordEntry{rec, std::chrono::steady_clock::now()};
    }
    return rec;
}

}  // namespace netscope
