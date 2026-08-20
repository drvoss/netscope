#include "json.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>

namespace netscope {
namespace {

// Mirrors the Go writer's state machine exactly: 2-space indent, one field or
// element per line, a leading "\n" before the first member and ",\n" before the
// rest.
class Writer {
public:
    std::string out;

    void openTop() {
        out += '{';
        push();
    }
    void closeTop() {
        pop();
        out += "}\n";
    }

    void beginObject(std::string_view key) {
        sep();
        padOut();
        if (!key.empty()) {
            quote(key);
            out += ": ";
        }
        out += '{';
        push();
    }
    void endObject() {
        if (first_.back()) {
            --indent_;
            first_.pop_back();
            out += '}';
            return;
        }
        pop();
        out += '}';
    }

    void beginArray(std::string_view key) {
        sep();
        padOut();
        quote(key);
        out += ": [";
        push();
    }
    void endArray() {
        if (first_.back()) {
            --indent_;
            first_.pop_back();
            out += ']';
            return;
        }
        pop();
        out += ']';
    }

    void raw(std::string_view key, std::string_view value) {
        sep();
        padOut();
        quote(key);
        out += ": ";
        out += value;
    }
    void str(std::string_view key, std::string_view value) {
        sep();
        padOut();
        quote(key);
        out += ": ";
        quote(value);
    }
    void boolean(std::string_view key, bool v) { raw(key, v ? "true" : "false"); }

    void integer(std::string_view key, long long v) { raw(key, std::to_string(v)); }
    void unsignedInt(std::string_view key, unsigned long long v) { raw(key, std::to_string(v)); }

    void millis(std::string_view key, Dur d) {
        integer(key, std::chrono::duration_cast<std::chrono::milliseconds>(d).count());
    }

    void optDouble(std::string_view key, const std::optional<double>& v) {
        if (!v) {
            raw(key, "null");
            return;
        }
        raw(key, formatF3(*v));
    }
    void optInt(std::string_view key, const std::optional<int>& v) {
        if (!v) {
            raw(key, "null");
            return;
        }
        integer(key, *v);
    }

    // Bare array element (no key).
    void element(std::string_view literal) {
        sep();
        padOut();
        out += literal;
    }
    void elementString(std::string_view value) {
        sep();
        padOut();
        quote(value);
    }
    void beginElementObject() {
        sep();
        padOut();
        out += '{';
        push();
    }

    void quote(std::string_view s) {
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        static constexpr char hex[] = "0123456789abcdef";
                        out += "\\u00";
                        out += hex[c >> 4];
                        out += hex[c & 0xf];
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        out += '"';
    }

private:
    int indent_ = 0;
    std::vector<bool> first_{true};

    void push() {
        ++indent_;
        first_.push_back(true);
    }
    void pop() {
        --indent_;
        first_.pop_back();
        out += '\n';
        padOut();
    }
    void sep() {
        if (first_.back()) {
            first_.back() = false;
            out += '\n';
        } else {
            out += ",\n";
        }
    }
    void padOut() {
        for (int i = 0; i < indent_; ++i) out += "  ";
    }
};

void writeStats(Writer& w, std::string_view key, const RttStats& s) {
    w.beginObject(key);
    w.integer("samples", s.samples);
    w.optDouble("lastMs", s.lastMs);
    w.optDouble("bestMs", s.bestMs);
    w.optDouble("avgMs", s.avgMs);
    w.optDouble("worstMs", s.worstMs);
    w.optDouble("jitterMs", s.jitterMs);
    w.optDouble("stdevMs", s.stdevMs);
    w.beginArray("spark");
    for (double v : s.spark) w.element(formatF3(v));
    w.endArray();
    w.endObject();
}

}  // namespace

std::string formatF3(double v) {
    std::array<char, 64> buf{};
    std::snprintf(buf.data(), buf.size(), "%.3f", v);
    std::string s(buf.data());
    if (s == "-0.000") return "0.000";
    return s;
}

std::string canonicalJson(const Snapshot& s) {
    Writer w;
    w.openTop();

    w.unsignedInt("revision", s.revision);
    w.unsignedInt("generation", s.generation);
    w.str("mode", modeName(s.mode));
    w.boolean("degraded", s.degraded);
    w.boolean("paused", s.paused);
    w.millis("nowMs", s.now);

    w.beginObject("target");
    w.str("input", s.target.input);
    w.str("ip", s.target.ip);
    w.str("family", familyName(s.target.family));
    w.millis("resolvedAtMs", s.target.resolvedAt);
    w.endObject();

    w.beginObject("cadence");
    w.integer("destIntervalMs", s.cadence.destIntervalMs);
    w.integer("midIntervalMs", s.cadence.midIntervalMs);
    w.integer("globalCapPps", s.cadence.globalCapPps);
    w.integer("windowDurationMs", s.cadence.windowDurationMs);
    w.integer("probeTimeoutMs", s.cadence.probeTimeoutMs);
    w.endObject();

    w.beginArray("hops");
    for (const auto& h : s.hops) {
        w.beginElementObject();
        w.integer("ttl", h.ttl);
        w.str("status", statusName(h.status));
        w.unsignedInt("sent", h.sent);
        w.unsignedInt("replied", h.replied);
        w.optDouble("lossPct", h.lossPct);
        w.str("primary", h.primary);
        w.boolean("isDestination", h.isDestination);
        writeStats(w, "stats", h.stats);
        w.beginArray("responders");
        for (const auto& r : h.responders) {
            w.beginElementObject();
            w.str("ip", r.ip);
            w.str("rdns", r.rdns);
            w.str("asn", r.asn);
            w.str("org", r.org);
            w.unsignedInt("seen", r.seen);
            w.millis("firstSeenAtMs", r.firstSeenAt);
            w.millis("lastSeenAtMs", r.lastSeenAt);
            writeStats(w, "stats", r.stats);
            w.endObject();
        }
        w.endArray();
        w.endObject();
    }
    w.endArray();

    w.beginObject("local");
    w.str("interface", s.local.interfaceName);
    w.str("address", s.local.address);
    w.str("gateway", s.local.gateway);
    w.beginArray("dnsServers");
    {
        // Sorted so the two implementations agree regardless of discovery order.
        std::vector<std::string> dns = s.local.dnsServers;
        std::sort(dns.begin(), dns.end());
        for (const auto& d : dns) w.elementString(d);
    }
    w.endArray();
    w.str("defaultRoute", s.local.defaultRoute);
    w.str("publicIp", s.local.publicIp);
    w.str("note", s.local.note);
    w.endObject();

    w.beginObject("health");
    w.integer("httpStatus", s.health.httpStatus);
    w.optDouble("httpLatencyMs", s.health.httpLatencyMs);
    w.str("httpNote", s.health.httpNote);
    w.integer("tcpPort", s.health.tcpPort);
    w.boolean("tcpOpen", s.health.tcpOpen);
    w.str("tcpNote", s.health.tcpNote);
    w.endObject();

    w.beginArray("events");
    for (const auto& e : s.events) {
        w.beginElementObject();
        w.millis("atMs", e.at);
        w.str("kind", eventKindName(e.kind));
        w.optInt("ttl", e.ttl);
        w.str("text", e.text);
        w.endObject();
    }
    w.endArray();

    w.closeTop();
    return w.out;
}

// ---------------------------------------------------------------- reader

const JsonValue* JsonValue::find(std::string_view key) const {
    for (const auto& kv : object) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

std::string JsonValue::strOr(std::string_view key, std::string_view fallback) const {
    const JsonValue* v = find(key);
    if (!v || v->type != Type::String) return std::string(fallback);
    return v->str;
}

double JsonValue::numOr(std::string_view key, double fallback) const {
    const JsonValue* v = find(key);
    if (!v || v->type != Type::Number) return fallback;
    return v->number;
}

long long JsonValue::intOr(std::string_view key, long long fallback) const {
    const JsonValue* v = find(key);
    if (!v || v->type != Type::Number) return fallback;
    return static_cast<long long>(v->number);
}

bool JsonValue::boolOr(std::string_view key, bool fallback) const {
    const JsonValue* v = find(key);
    if (!v || v->type != Type::Bool) return fallback;
    return v->boolean;
}

std::optional<double> JsonValue::optNum(std::string_view key) const {
    const JsonValue* v = find(key);
    if (!v || v->type != Type::Number) return std::nullopt;
    return v->number;
}

std::vector<std::string> JsonValue::stringsAt(std::string_view key) const {
    std::vector<std::string> out;
    const JsonValue* v = find(key);
    if (!v || v->type != Type::Array) return out;
    for (const auto& e : v->array) {
        if (e.type == Type::String) out.push_back(e.str);
    }
    return out;
}

namespace {

class Parser {
public:
    Parser(std::string_view text) : s_(text) {}

    bool parse(JsonValue& out) {
        skipWs();
        if (!parseValue(out)) return false;
        skipWs();
        return true;
    }

    std::string error;

private:
    std::string_view s_;
    std::size_t i_ = 0;

    void skipWs() {
        while (i_ < s_.size() &&
               (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) {
            ++i_;
        }
    }

    bool fail(const char* what) {
        error = std::string(what) + " at offset " + std::to_string(i_);
        return false;
    }

    bool literal(std::string_view lit) {
        if (s_.compare(i_, lit.size(), lit) != 0) return false;
        i_ += lit.size();
        return true;
    }

    bool parseValue(JsonValue& out) {
        if (i_ >= s_.size()) return fail("unexpected end of input");
        switch (s_[i_]) {
            case '{': return parseObject(out);
            case '[': return parseArray(out);
            case '"':
                out.type = JsonValue::Type::String;
                return parseString(out.str);
            case 't':
                if (!literal("true")) return fail("bad literal");
                out.type = JsonValue::Type::Bool;
                out.boolean = true;
                return true;
            case 'f':
                if (!literal("false")) return fail("bad literal");
                out.type = JsonValue::Type::Bool;
                out.boolean = false;
                return true;
            case 'n':
                if (!literal("null")) return fail("bad literal");
                out.type = JsonValue::Type::Null;
                return true;
            default: return parseNumber(out);
        }
    }

    bool parseObject(JsonValue& out) {
        out.type = JsonValue::Type::Object;
        ++i_;  // '{'
        skipWs();
        if (i_ < s_.size() && s_[i_] == '}') {
            ++i_;
            return true;
        }
        for (;;) {
            skipWs();
            std::string key;
            if (i_ >= s_.size() || s_[i_] != '"') return fail("expected object key");
            if (!parseString(key)) return false;
            skipWs();
            if (i_ >= s_.size() || s_[i_] != ':') return fail("expected ':'");
            ++i_;
            skipWs();
            JsonValue val;
            if (!parseValue(val)) return false;
            out.object.emplace_back(std::move(key), std::move(val));
            skipWs();
            if (i_ >= s_.size()) return fail("unterminated object");
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == '}') {
                ++i_;
                return true;
            }
            return fail("expected ',' or '}'");
        }
    }

    bool parseArray(JsonValue& out) {
        out.type = JsonValue::Type::Array;
        ++i_;  // '['
        skipWs();
        if (i_ < s_.size() && s_[i_] == ']') {
            ++i_;
            return true;
        }
        for (;;) {
            skipWs();
            JsonValue val;
            if (!parseValue(val)) return false;
            out.array.push_back(std::move(val));
            skipWs();
            if (i_ >= s_.size()) return fail("unterminated array");
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == ']') {
                ++i_;
                return true;
            }
            return fail("expected ',' or ']'");
        }
    }

    bool parseString(std::string& out) {
        ++i_;  // opening quote
        out.clear();
        while (i_ < s_.size()) {
            char c = s_[i_++];
            if (c == '"') return true;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i_ >= s_.size()) break;
            char esc = s_[i_++];
            switch (esc) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (i_ + 4 > s_.size()) return fail("truncated \\u escape");
                    unsigned code = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = s_[i_ + static_cast<std::size_t>(k)];
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                        else return fail("bad \\u escape");
                    }
                    i_ += 4;
                    // Scenario files are ASCII/UTF-8; emit UTF-8 for the BMP range.
                    if (code < 0x80) {
                        out += static_cast<char>(code);
                    } else if (code < 0x800) {
                        out += static_cast<char>(0xC0 | (code >> 6));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    } else {
                        out += static_cast<char>(0xE0 | (code >> 12));
                        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    }
                    break;
                }
                default: return fail("unknown escape");
            }
        }
        return fail("unterminated string");
    }

    bool parseNumber(JsonValue& out) {
        std::size_t start = i_;
        if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
        bool any = false;
        while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) {
            ++i_;
            any = true;
        }
        if (i_ < s_.size() && s_[i_] == '.') {
            ++i_;
            while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) {
                ++i_;
                any = true;
            }
        }
        if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
            while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) ++i_;
        }
        if (!any) return fail("expected a value");
        out.type = JsonValue::Type::Number;
        out.number = std::strtod(std::string(s_.substr(start, i_ - start)).c_str(), nullptr);
        return true;
    }
};

}  // namespace

std::optional<JsonValue> parseJson(std::string_view text, std::string& err) {
    Parser p(text);
    JsonValue v;
    if (!p.parse(v)) {
        err = p.error;
        return std::nullopt;
    }
    return v;
}

}  // namespace netscope
