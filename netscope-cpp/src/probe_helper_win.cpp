// Windows IP Helper backend (spec §6.2 rank "helper").
//
// Why this rather than a raw socket: on Windows a raw ICMP socket receives Echo
// Replies but NOT the Time Exceeded messages that intermediate routers send, so a
// raw-socket traceroute sees only the destination and reports every intermediate
// hop as silent. IcmpSendEcho reports TTL expiry explicitly via
// IP_TTL_EXPIRED_TRANSIT together with the responding router's address, which is
// exactly what the path table needs. Both plan §5.2 and the cross-review point at
// this API for Windows.
//
// The SYNCHRONOUS form is used deliberately. All three reviewers flagged the
// asynchronous IcmpSendEcho2 reply-buffer lifetime as a teardown hazard: the API
// writes into a caller-owned buffer after returning, so a shutdown that frees the
// buffer or closes the handle first is a use-after-free. Keeping the call
// synchronous confines the buffer's lifetime to one stack frame and removes that
// class of bug entirely; the concurrency it costs is irrelevant at a 10 pps cap.
#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "net_compat.h"
#include "probe.h"
#include "stats.h"

namespace netscope {
namespace {

// IP_STATUS codes (ipexport.h).
constexpr DWORD kIpSuccess = 0;
constexpr DWORD kIpBufTooSmall = 11001;
constexpr DWORD kIpDestNetUnreachable = 11002;
constexpr DWORD kIpDestHostUnreachable = 11003;
constexpr DWORD kIpDestProtUnreachable = 11004;
constexpr DWORD kIpDestPortUnreachable = 11005;
constexpr DWORD kIpReqTimedOut = 11010;
constexpr DWORD kIpTtlExpiredTransit = 11013;
constexpr DWORD kIpTtlExpiredReassem = 11014;
constexpr DWORD kIpDestUnreachable = 11040;
constexpr DWORD kIpDestNoRoute = 11041;
constexpr DWORD kIpDestAdminProhibited = 11043;

std::string statusNote(DWORD status) {
    switch (status) {
        case kIpDestNetUnreachable: return "net unreachable";
        case kIpDestHostUnreachable: return "host unreachable";
        case kIpDestProtUnreachable: return "protocol unreachable";
        case kIpDestPortUnreachable: return "port unreachable";
        case kIpDestNoRoute: return "no route";
        case kIpDestAdminProhibited: return "administratively prohibited";
        default: return "destination unreachable";
    }
}

// On 64-bit Windows IcmpSendEcho stores ICMP_ECHO_REPLY32 records and expects
// IP_OPTION_INFORMATION32: their pointer fields are 32 bits wide, so the structures
// are 28 and 8 bytes rather than the 40 and 16 that native pointers would give.
// Using the *_32 types makes the layout ABI-correct instead of merely agreeing on
// the first few offsets (codex HIGH finding).
#ifdef _WIN64
using ReplyRecord = ICMP_ECHO_REPLY32;
using OptionInfo = IP_OPTION_INFORMATION32;
#else
using ReplyRecord = ICMP_ECHO_REPLY;
using OptionInfo = IP_OPTION_INFORMATION;
#endif

std::string ipv4Text(IPAddr addr) {
    in_addr a{};
    a.S_un.S_addr = addr;
    std::array<char, INET_ADDRSTRLEN> buf{};
    if (::inet_ntop(AF_INET, &a, buf.data(), buf.size()) == nullptr) return "";
    return std::string(buf.data());
}

class HelperBackend final : public Backend {
public:
    HelperBackend(std::string targetIp, IPAddr dst) : targetIp_(std::move(targetIp)), dst_(dst) {}

    ProbeMode mode() const override { return ProbeMode::Helper; }
    bool supportsPerTTL() const override { return true; }

    std::vector<ProbeResult> traceRound(std::uint64_t, int, std::stop_token) override { return {}; }

    // Each probe owns its own ICMP handle and closes it before returning, so there
    // is no shared handle to invalidate and no reply buffer outliving its frame
    // (spec §3.3).
    void close() override { closed_.store(true); }

    ProbeResult probe(const ProbeID& id, std::stop_token stop) override {
        ProbeResult res;
        res.id = id;
        res.sentAt = elapsedSinceStart();

        if (closed_.load() || stop.stop_requested()) {
            res.outcome = Outcome::BackendError;
            res.note = "backend closed";
            res.recvAt = res.sentAt;
            return res;
        }
        if (id.ttl < 1 || id.ttl > 255) {
            res.outcome = Outcome::BackendError;
            res.note = "ttl out of range";
            res.recvAt = res.sentAt;
            return res;
        }

        HANDLE handle = ::IcmpCreateFile();
        if (handle == INVALID_HANDLE_VALUE) {
            res.outcome = Outcome::PermissionDenied;
            res.note = "IcmpCreateFile failed (error " + std::to_string(::GetLastError()) + ")";
            res.recvAt = elapsedSinceStart();
            return res;
        }

        static const char kPayload[] = "netscope";
        constexpr WORD kPayloadSize = sizeof(kPayload) - 1;

        OptionInfo opts{};
        // This is what makes the probe TTL-limited toward the target rather than a
        // ping of the router's own address (spec §1).
        opts.Ttl = static_cast<UCHAR>(id.ttl);

        // One reply record, the echoed payload, and slack for the trailer the API
        // may append. Sized for the larger of the two record layouts.
        constexpr std::size_t kRecordSize =
            sizeof(ICMP_ECHO_REPLY) > sizeof(ReplyRecord) ? sizeof(ICMP_ECHO_REPLY)
                                                          : sizeof(ReplyRecord);
        std::vector<unsigned char> reply(kRecordSize + kPayloadSize + 8 + 64, 0);

        const DWORD timeoutMs = static_cast<DWORD>(
            std::chrono::duration_cast<std::chrono::milliseconds>(kProbeTimeout).count());

        const Dur sentAt = elapsedSinceStart();
        res.sentAt = sentAt;

        const DWORD n = ::IcmpSendEcho(handle, dst_, const_cast<char*>(kPayload), kPayloadSize,
                                       reinterpret_cast<PIP_OPTION_INFORMATION>(&opts),
                                       reply.data(), static_cast<DWORD>(reply.size()), timeoutMs);
        const DWORD lastError = ::GetLastError();
        ::IcmpCloseHandle(handle);

        res.recvAt = elapsedSinceStart();
        // Application-level round trip, matching the Go build and the POSIX raw
        // backend, rather than the API's integer-millisecond RoundTripTime
        // (spec §4.1).
        res.rtt = res.recvAt - sentAt;

        if (stop.stop_requested()) {
            res.outcome = Outcome::Timeout;
            res.note = "cancelled";
            return res;
        }

        DWORD status = kIpReqTimedOut;
        std::string responder;
        if (n > 0) {
            // IcmpSendEcho returns the NUMBER OF REPLY RECORDS stored, and stores
            // one for TTL expiry and unreachables too -- their IP_STATUS is in the
            // record.
            const auto* echo = reinterpret_cast<const ReplyRecord*>(reply.data());
            status = echo->Status;
            responder = ipv4Text(echo->Address);
        } else {
            // Zero means NO record was stored, so the reply buffer holds nothing
            // defined. Reading an address out of it here would be reading
            // uninitialized memory; the status comes from GetLastError alone.
            status = lastError;
        }

        // A reply that took longer than probeTimeout must be reported as a timeout,
        // not dropped: dropping it would lose the transmission from both the sent
        // and the loss counts (codex HIGH finding).
        if (res.rtt > kProbeTimeout && status != kIpReqTimedOut) {
            status = kIpReqTimedOut;
            res.note = "reply arrived after the timeout";
        }

        switch (status) {
            case kIpSuccess:
                res.outcome = Outcome::Reply;
                res.responder = targetIp_;
                break;

            case kIpTtlExpiredTransit:
            case kIpTtlExpiredReassem:
                res.outcome = Outcome::TTLExpired;
                res.responder = responder;
                if (res.responder.empty()) {
                    // No address means we cannot attribute the hop; treat it as
                    // silence rather than inventing a responder.
                    res.outcome = Outcome::Timeout;
                    res.recvAt = sentAt + kProbeTimeout;
                    res.rtt = Dur::zero();
                }
                break;

            case kIpDestNetUnreachable:
            case kIpDestHostUnreachable:
            case kIpDestProtUnreachable:
            case kIpDestPortUnreachable:
            case kIpDestUnreachable:
            case kIpDestNoRoute:
            case kIpDestAdminProhibited:
                res.outcome = Outcome::Unreachable;
                res.responder = responder;
                res.note = statusNote(status);
                break;

            case kIpReqTimedOut:
                res.outcome = Outcome::Timeout;
                res.recvAt = sentAt + kProbeTimeout;
                res.rtt = Dur::zero();
                break;

            case kIpBufTooSmall:
                res.outcome = Outcome::BackendError;
                res.note = "reply buffer too small";
                break;

            default:
                res.outcome = Outcome::BackendError;
                res.note = "IP_STATUS " + std::to_string(status);
                break;
        }
        return res;
    }

private:
    std::string targetIp_;
    IPAddr dst_;
    std::atomic<bool> closed_{false};
};

}  // namespace

std::unique_ptr<Backend> makeHelperBackend(const std::string& targetIp, std::string& err) {
    netInit();

    in_addr v4{};
    if (::inet_pton(AF_INET, targetIp.c_str(), &v4) != 1) {
        // Icmp6SendEcho2 needs a bound source address and a different reply
        // layout; IPv6 on Windows is out of scope for this backend.
        err = "IP Helper backend supports IPv4 only";
        return nullptr;
    }

    HANDLE probeHandle = ::IcmpCreateFile();
    if (probeHandle == INVALID_HANDLE_VALUE) {
        err = "IcmpCreateFile failed (error " + std::to_string(::GetLastError()) + ")";
        return nullptr;
    }
    ::IcmpCloseHandle(probeHandle);

    return std::make_unique<HelperBackend>(targetIp, v4.S_un.S_addr);
}

}  // namespace netscope
