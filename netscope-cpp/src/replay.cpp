#include "replay.h"

#include <fstream>
#include <sstream>

#include "engine.h"
#include "json.h"

namespace netscope {
namespace {

bool readFile(const std::string& path, std::string& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        return false;
    }
    std::ostringstream os;
    os << in.rdbuf();
    out = os.str();
    return true;
}

}  // namespace

std::shared_ptr<const Snapshot> replayFile(const std::string& path, std::string& err) {
    std::string text;
    if (!readFile(path, text, err)) return nullptr;

    auto doc = parseJson(text, err);
    if (!doc) {
        err = path + ": " + err;
        return nullptr;
    }
    if (doc->type != JsonValue::Type::Object) {
        err = path + ": top level is not an object";
        return nullptr;
    }

    const JsonValue* targetObj = doc->find("target");
    Target target;
    Family family = Family::IP4;
    if (targetObj && targetObj->type == JsonValue::Type::Object) {
        target.input = targetObj->strOr("input");
        target.ip = targetObj->strOr("ip");
        family = familyFromName(targetObj->strOr("family", "ip4"));
        target.family = family;
        target.resolvedAt = ms(targetObj->intOr("resolvedAtMs", 0));
    }

    Engine eng(target, modeFromName(doc->strOr("mode", "raw")));

    if (const JsonValue* l = doc->find("local"); l && l->type == JsonValue::Type::Object) {
        LocalInfo info;
        info.interfaceName = l->strOr("interface");
        info.address = l->strOr("address");
        info.gateway = l->strOr("gateway");
        info.dnsServers = l->stringsAt("dnsServers");
        info.defaultRoute = l->strOr("defaultRoute");
        info.publicIp = l->strOr("publicIp");
        info.note = l->strOr("note");
        eng.setLocal(std::move(info));
    }

    if (const JsonValue* h = doc->find("health"); h && h->type == JsonValue::Type::Object) {
        Health health;
        health.httpStatus = static_cast<int>(h->intOr("httpStatus", 0));
        health.httpLatencyMs = h->optNum("httpLatencyMs");
        health.httpNote = h->strOr("httpNote");
        health.tcpPort = static_cast<int>(h->intOr("tcpPort", 0));
        health.tcpOpen = h->boolOr("tcpOpen", false);
        health.tcpNote = h->strOr("tcpNote");
        eng.setHealth(std::move(health));
    }

    const JsonValue* steps = doc->find("steps");
    if (steps && steps->type == JsonValue::Type::Array) {
        for (const JsonValue& st : steps->array) {
            if (st.type != JsonValue::Type::Object) continue;
            const std::string kind = st.strOr("kind");
            const Dur at = ms(st.intOr("tMs", 0));

            if (kind == "probe") {
                ProbeResult r;
                r.id.generation = eng.generation();
                r.id.family = family;
                r.id.ttl = static_cast<int>(st.intOr("ttl", 0));
                r.id.attempt = static_cast<std::uint64_t>(st.intOr("attempt", 0));
                r.outcome = outcomeFromName(st.strOr("outcome", "Timeout"));
                r.responder = st.strOr("responder");
                r.sentAt = at;
                if (answered(r.outcome)) {
                    r.rtt = fromMs(st.numOr("rttMs", 0));
                    r.recvAt = at + r.rtt;
                } else {
                    r.recvAt = at + ms(eng.cadence().probeTimeoutMs);
                }
                r.note = st.strOr("text");
                eng.ingest(r);

            } else if (kind == "enrich") {
                eng.applyEnrich(st.strOr("ip"), st.strOr("rdns"), st.strOr("asn"), st.strOr("org"));

            } else if (kind == "trace-round") {
                eng.endTraceRound(at);

            } else if (kind == "snapshot") {
                // Classification is stateful (hysteresis), so the scenario
                // controls exactly when snapshots are taken.
                eng.snapshot(at);

            } else if (kind == "event") {
                std::optional<int> ttl;
                const int t = static_cast<int>(st.intOr("ttl", 0));
                if (t != 0) ttl = t;
                eng.addEvent(at, eventKindFromName(st.strOr("eventKind", "start")), ttl,
                             st.strOr("text"));

            } else if (kind == "pause") {
                eng.togglePause(at);

            } else if (kind == "reprobe") {
                eng.reprobe(at);
            }
        }
    }

    return eng.snapshot(ms(doc->intOr("emitAtMs", 0)));
}

}  // namespace netscope
