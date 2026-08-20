// Deterministic replay (spec §9).
//
// A scenario file supplies a virtual monotonic clock and a fixed stream of
// ProbeResults. Replaying it opens no sockets and reads no real clock, so both
// binaries can be fed the identical stream and their canonical JSON snapshots
// compared byte for byte. Mirroring directory names does not demonstrate parity;
// this does.
//
// The scenario schema must stay in sync with the Go implementation's
// internal/engine/replay.go.
#pragma once

#include <memory>
#include <string>

#include "model.h"

namespace netscope {

// Loads and replays a scenario file. Returns nullptr and sets err on failure.
std::shared_ptr<const Snapshot> replayFile(const std::string& path, std::string& err);

}  // namespace netscope
