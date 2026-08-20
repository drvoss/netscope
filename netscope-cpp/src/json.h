// Canonical JSON output and a minimal JSON reader.
//
// The writer is hand-rolled so its output is BYTE-IDENTICAL to the Go
// implementation's internal/model/json.go. That byte equality is what the parity
// harness compares (spec §9), so the two emitters must be changed together.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "model.h"

namespace netscope {

// Renders a float with exactly three decimals, normalizing -0. Both
// implementations must agree on this exact rendering.
std::string formatF3(double v);

// Serializes a snapshot for parity comparison.
std::string canonicalJson(const Snapshot& s);

// ---------------------------------------------------------------- reader

// JsonValue is a tiny DOM, enough for the shallow scenario schema. A full parser
// is not needed and would be one more thing to keep in sync.
struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0;
    std::string str;
    std::vector<JsonValue> array;
    std::vector<std::pair<std::string, JsonValue>> object;

    const JsonValue* find(std::string_view key) const;

    std::string strOr(std::string_view key, std::string_view fallback = "") const;
    double numOr(std::string_view key, double fallback = 0) const;
    long long intOr(std::string_view key, long long fallback = 0) const;
    bool boolOr(std::string_view key, bool fallback = false) const;
    std::optional<double> optNum(std::string_view key) const;
    std::vector<std::string> stringsAt(std::string_view key) const;
};

// Parses text. Returns nullopt and sets err on failure.
std::optional<JsonValue> parseJson(std::string_view text, std::string& err);

}  // namespace netscope
