// Fills the LOCAL IF / ROUTE panel.
//
// The platform-specific parts sit behind this contract so the panel never renders
// silently blank: when a platform cannot answer, it says so in LocalInfo::note
// rather than leaving empty fields (spec §6.5, cross-review R1-1 #9).
#pragma once

#include <string>
#include <vector>

#include "model.h"

namespace netscope {

// Collects local addressing for the route toward targetIp.
LocalInfo gatherSysinfo(const std::string& targetIp, bool wantPublicIp);

// Platform hooks, implemented per OS inside sysinfo.cpp.
struct RouteInfo {
    std::string gateway;
    std::string defaultRoute;
    std::string note;
};
RouteInfo platformRouteInfo();

struct DnsInfo {
    std::vector<std::string> servers;
    std::string note;
};
DnsInfo platformDnsServers();

}  // namespace netscope
