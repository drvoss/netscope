// DNS resolution and ASN/org ownership lookup.
//
// This is a separate subsystem with its own cache, not a step inside the probe
// loop: rDNS and Cymru TXT lookups can stall for seconds and must never hold up
// measurement (spec §7, cross-review R1-1 #8).
#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "model.h"

namespace netscope {

// Cache TTLs (spec §7).
inline constexpr auto kRdnsTTL = std::chrono::minutes(10);
inline constexpr auto kAsnTTL = std::chrono::minutes(60);
inline constexpr auto kDnsTTL = std::chrono::minutes(5);

struct EnrichResult {
    std::string ip;
    std::string rdns;
    std::string asn;
    std::string org;
};

// Resolves user input to a target, preferring IPv4 so the default path matches
// what most users expect from ping/tracert. Returns false and sets err on failure.
bool resolveTarget(const std::string& input, Target& out, std::string& err);

class EnrichCache {
public:
    // Fills rDNS and ASN/org for one IP.
    //
    // Private, loopback, link-local and CGNAT addresses are never sent to a public
    // resolver: they are meaningless to Cymru and leaking a network's internal
    // topology to a third party would be rude at best (spec §7).
    EnrichResult lookup(const std::string& ip);

    // Drops cached values so a manual refresh (keys d / w) actually re-queries.
    void invalidate(const std::string& ip, bool dns, bool asn);

    // Forward and reverse records for the RESOLVE panel.
    Records lookupRecords(const std::string& host);

private:
    struct Entry {
        std::string value;
        std::chrono::steady_clock::time_point at;
    };

    std::optional<std::string> get(std::map<std::string, Entry>& m, const std::string& key,
                                   std::chrono::steady_clock::duration ttl);
    void put(std::map<std::string, Entry>& m, const std::string& key, const std::string& value);

    std::string reverseDNS(const std::string& ip);
    void asnLookup(const std::string& ip, std::string& asn, std::string& org);

    struct RecordEntry {
        Records value;
        std::chrono::steady_clock::time_point at;
    };

    std::mutex mu_;
    std::map<std::string, Entry> rdns_;
    std::map<std::string, Entry> asn_;
    std::map<std::string, Entry> org_;
    std::map<std::string, RecordEntry> records_;
};

// Queries TXT records. Implemented with the platform resolver; returns an empty
// vector on any failure. Exposed for testing the Cymru parsing.
std::vector<std::string> lookupTXT(const std::string& name);

// Builds the reversed query name for Team Cymru's origin service. Returns "" when
// ip is not an address.
std::string cymruOriginName(const std::string& ip);

// Parses the first field of a Cymru origin TXT record ("15133 | 93.184.216.0/24 |
// US | arin | ..."), returning "" when it is not a plain ASN number.
std::string cymruFirstField(const std::string& txt);

// Parses the org name out of an AS description TXT record
// ("15133 | US | arin | 2007-03-23 | EDGECAST, US").
std::string cymruOrgField(const std::string& txt);

}  // namespace netscope
