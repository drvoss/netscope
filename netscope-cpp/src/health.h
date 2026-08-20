// L7 and port checks shown in the mid bar.
//
// These results are kept independent of hop classification on purpose: ICMP can be
// blocked end to end while HTTP works perfectly, and conflating the two would make
// the dashboard lie in both directions (spec §6.5).
#pragma once

#include <string>

#include "model.h"

namespace netscope {

// Performs an HTTP status probe and a TCP connect probe.
//
// host is the name the user typed (so TLS SNI and the Host header are right);
// ip is the resolved address actually being measured, so the check follows the
// same path as the probes rather than re-resolving to a different CDN node.
Health checkHealth(const std::string& host, const std::string& ip, int port, Dur now);

// Asks a public reflector for our externally visible address. Returns "" on any
// failure. This is the one outbound call NetScope makes to a third party that is
// not the user's chosen target; the plan's header spec requires "pub-ip". Disabled
// with --no-public-ip.
std::string fetchPublicIp();

}  // namespace netscope
