// Thin platform shim for the socket headers and IP-literal handling.
//
// The Windows/POSIX split the plan asks for (§5.3) is confined to this header
// plus the *_win / *_posix translation units, so the rest of the code stays
// portable.
#pragma once

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// icmpapi.h must follow iphlpapi.h: it depends on the IP_OPTION_INFORMATION and
// ICMP_ECHO_REPLY definitions that ipexport.h brings in.
#include <icmpapi.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <string>
#include <string_view>

namespace netscope {

// Initializes Winsock once per process. A no-op elsewhere. Safe to call
// repeatedly and from multiple threads.
void netInit();

// Parses an IP literal and returns its canonical text form, or "" if the input is
// not an address. Canonicalization matters for parity: the Go side uses
// net.ParseIP().String(), and inet_pton + inet_ntop produce the same form
// (lowercase, compressed IPv6).
std::string parseIPLiteral(std::string_view s);

// True when the address should be excluded from public lookups: RFC1918,
// loopback, link-local, multicast, unspecified, or RFC 6598 CGNAT (spec §7).
bool isPrivateOrReserved(std::string_view ip);

}  // namespace netscope
