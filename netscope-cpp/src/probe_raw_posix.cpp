// POSIX raw / datagram ICMP backend (spec §6.2 rank "raw").
//
// One shared socket, a single receiver thread, and correlation by sequence number.
// Correlation keys on the sequence alone, which is unique per process run
// (spec §6.3). The ICMP id is a *filter*, not a key, and only on a raw socket:
// there we see other processes' replies too, so an id mismatch discards the packet
// before it can collide with our sequence numbering. On Linux's unprivileged ICMP
// datagram socket the kernel rewrites the id, so checking it there would silently
// drop every reply -- hence the isRaw_ guard at each check.
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>

#include "net_compat.h"
#include "probe.h"
#include "stats.h"

namespace netscope {
namespace {

std::uint16_t checksum16(const unsigned char* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>(data[i] << 8 | data[i + 1]);
    }
    if (len % 2 != 0) sum += static_cast<std::uint32_t>(data[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

struct Reply {
    std::string responder;
    Outcome outcome = Outcome::Timeout;
    Dur at{};
    std::string note;
};

std::string unreachNote4(int code) {
    switch (code) {
        case ICMP_NET_UNREACH: return "net unreachable";
        case ICMP_HOST_UNREACH: return "host unreachable";
        case ICMP_PROT_UNREACH: return "protocol unreachable";
        case ICMP_PORT_UNREACH: return "port unreachable";
        case ICMP_NET_ANO:
        case ICMP_HOST_ANO: return "administratively prohibited";
        case 13: return "communication administratively prohibited";
        default: return "code " + std::to_string(code);
    }
}

std::string unreachNote6(int code) {
    switch (code) {
        case ICMP6_DST_UNREACH_NOROUTE: return "no route";
        case ICMP6_DST_UNREACH_ADMIN: return "administratively prohibited";
        case ICMP6_DST_UNREACH_ADDR: return "address unreachable";
        case ICMP6_DST_UNREACH_NOPORT: return "port unreachable";
        default: return "code " + std::to_string(code);
    }
}

// Pulls the identifier and sequence number out of the original datagram that a
// Time Exceeded or Destination Unreachable message quotes back to us.
bool quotedIdSeq(const unsigned char* data, std::size_t len, Family family, std::uint16_t& id,
                 std::uint16_t& seq) {
    std::size_t off = 0;
    if (family == Family::IP4) {
        if (len < 20) return false;
        std::size_t ihl = static_cast<std::size_t>(data[0] & 0x0f) * 4;
        if (ihl < 20) ihl = 20;
        off = ihl;
    } else {
        off = 40;  // fixed IPv6 header
    }
    // original ICMP header: type(1) code(1) checksum(2) id(2) seq(2)
    if (len < off + 8) return false;
    id = static_cast<std::uint16_t>(data[off + 4] << 8 | data[off + 5]);
    seq = static_cast<std::uint16_t>(data[off + 6] << 8 | data[off + 7]);
    return true;
}

class RawBackend final : public Backend {
public:
    RawBackend(std::string targetIp, Family family, int fd, bool isRaw, sockaddr_storage dst,
               socklen_t dstLen)
        : targetIp_(std::move(targetIp)),
          family_(family),
          fd_(fd),
          isRaw_(isRaw),
          dst_(dst),
          dstLen_(dstLen) {
        receiver_ = std::thread([this] { receiveLoop(); });
    }

    ~RawBackend() override { close(); }

    ProbeMode mode() const override { return ProbeMode::Raw; }
    bool supportsPerTTL() const override { return true; }
    std::vector<ProbeResult> traceRound(std::uint64_t, int, std::stop_token) override { return {}; }

    // Closing the socket unblocks the sender; the receiver is woken by its own poll
    // timeout, which is what actually bounds the join. Closing a descriptor in one
    // thread is NOT a portable guarantee that another thread blocked in recvfrom
    // wakes up, so the receiver never blocks indefinitely in the first place
    // (codex HIGH finding).
    void close() override {
        bool expected = false;
        if (!closed_.compare_exchange_strong(expected, true)) return;

        // Serialize against an in-flight setTTL/sendto so neither operates on a
        // descriptor that is being closed and possibly reused.
        std::lock_guard<std::mutex> sendLock(sendMu_);
        const int fd = fd_.exchange(-1);
        if (fd >= 0) {
            ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
        // Wake everyone still waiting so no worker blocks for its full timeout.
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& kv : pending_) kv.second.done = true;
        }
        cv_.notify_all();
        if (receiver_.joinable()) receiver_.join();
    }

    ProbeResult probe(const ProbeID& id, std::stop_token stop) override {
        ProbeResult res;
        res.id = id;

        const std::uint16_t seq = static_cast<std::uint16_t>(++seq_ & 0x7fff);

        if (closed_.load()) {
            res.outcome = Outcome::BackendError;
            res.note = "backend closed";
            res.sentAt = elapsedSinceStart();
            res.recvAt = res.sentAt;
            return res;
        }

        {
            std::lock_guard<std::mutex> lk(mu_);
            pending_[seq] = Pending{};
        }

        std::vector<unsigned char> packet(16, 0);
        if (family_ == Family::IP4) {
            packet[0] = ICMP_ECHO;
        } else {
            packet[0] = ICMP6_ECHO_REQUEST;
        }
        packet[1] = 0;
        packet[4] = static_cast<unsigned char>((id_ >> 8) & 0xff);
        packet[5] = static_cast<unsigned char>(id_ & 0xff);
        packet[6] = static_cast<unsigned char>(seq >> 8);
        packet[7] = static_cast<unsigned char>(seq & 0xff);
        std::memcpy(packet.data() + 8, "netscope", 8);
        if (family_ == Family::IP4) {
            // The kernel fills the checksum for ICMPv6.
            const std::uint16_t ck = checksum16(packet.data(), packet.size());
            packet[2] = static_cast<unsigned char>(ck >> 8);
            packet[3] = static_cast<unsigned char>(ck & 0xff);
        }

        Dur sentAt{};
        ssize_t sent = -1;
        int sendErrno = 0;
        {
            // TTL is a socket-level option, so setting it and sending must be
            // serialized or concurrent senders would clobber each other's TTL. The
            // same lock keeps close() from pulling the descriptor out from under us.
            std::lock_guard<std::mutex> lk(sendMu_);
            const int fd = fd_.load();
            sentAt = elapsedSinceStart();
            if (fd < 0) {
                res.outcome = Outcome::BackendError;
                res.note = "backend closed";
                res.sentAt = sentAt;
                res.recvAt = sentAt;
                forget(seq);
                return res;
            }
            if (!setTTL(fd, id.ttl, sendErrno)) {
                res.outcome = Outcome::BackendError;
                res.note = std::string("set ttl: ") + std::strerror(sendErrno);
                res.sentAt = sentAt;
                res.recvAt = sentAt;
                forget(seq);
                return res;
            }
            sent = ::sendto(fd, packet.data(), packet.size(), 0,
                            reinterpret_cast<const sockaddr*>(&dst_), dstLen_);
            sendErrno = errno;
        }

        res.sentAt = sentAt;
        if (sent < 0) {
            res.outcome = (sendErrno == EACCES || sendErrno == EPERM) ? Outcome::PermissionDenied
                                                                     : Outcome::BackendError;
            res.note = std::strerror(sendErrno);
            res.recvAt = elapsedSinceStart();
            forget(seq);
            return res;
        }

        Reply reply;
        bool got = false;
        {
            std::unique_lock<std::mutex> lk(mu_);
            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                kProbeTimeout);
            auto it = pending_.find(seq);
            cv_.wait_until(lk, deadline, [&] {
                it = pending_.find(seq);
                return it == pending_.end() || it->second.done || stop.stop_requested();
            });
            it = pending_.find(seq);
            if (it != pending_.end()) {
                got = it->second.got;
                reply = it->second.reply;
                pending_.erase(it);
            }
        }

        if (got) {
            // A reply can win the race against the deadline by a hair and still be
            // later than probeTimeout. Converting it here rather than letting the
            // engine drop it keeps the transmission counted: dropping the result
            // entirely would lose both the sent and the loss (codex HIGH finding).
            if (reply.at - sentAt > kProbeTimeout) {
                res.outcome = Outcome::Timeout;
                res.recvAt = sentAt + kProbeTimeout;
                res.note = "reply arrived after the timeout";
                return res;
            }
            res.outcome = reply.outcome;
            res.responder = reply.responder;
            res.recvAt = reply.at;
            res.rtt = reply.at > sentAt ? reply.at - sentAt : Dur::zero();
            res.note = reply.note;
            return res;
        }
        if (closed_.load()) {
            res.outcome = Outcome::BackendError;
            res.note = "backend closed";
            res.recvAt = elapsedSinceStart();
            return res;
        }
        if (stop.stop_requested()) {
            res.outcome = Outcome::Timeout;
            res.note = "cancelled";
            res.recvAt = elapsedSinceStart();
            return res;
        }
        res.outcome = Outcome::Timeout;
        res.recvAt = sentAt + kProbeTimeout;
        return res;
    }

private:
    struct Pending {
        bool got = false;
        bool done = false;
        Reply reply;
    };

    void forget(std::uint16_t seq) {
        std::lock_guard<std::mutex> lk(mu_);
        pending_.erase(seq);
    }

    bool setTTL(int fd, int ttl, int& err) {
        int value = ttl;
        int rc = 0;
        if (family_ == Family::IP4) {
            rc = ::setsockopt(fd, IPPROTO_IP, IP_TTL, &value, sizeof(value));
        } else {
            rc = ::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &value, sizeof(value));
        }
        err = errno;
        return rc == 0;
    }

    void deliver(std::uint16_t seq, const Reply& reply) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = pending_.find(seq);
            if (it == pending_.end()) {
                // Late or foreign reply: dropping it keeps avg and jitter clean
                // (spec §6.3).
                return;
            }
            it->second.got = true;
            it->second.done = true;
            it->second.reply = reply;
        }
        cv_.notify_all();
    }

    void receiveLoop() {
        std::vector<unsigned char> buf(2048);
        for (;;) {
            if (closed_.load()) return;
            const int fd = fd_.load();
            if (fd < 0) return;

            // poll with a short timeout rather than a blocking recvfrom: the loop
            // then re-checks closed_ at least five times a second, which is what
            // makes the receiver's join bounded on every platform.
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            const int ready = ::poll(&pfd, 1, 200);
            if (ready < 0) {
                if (errno == EINTR) continue;
                return;
            }
            if (ready == 0) continue;

            sockaddr_storage from{};
            socklen_t fromLen = sizeof(from);
            ssize_t n = ::recvfrom(fd, buf.data(), buf.size(), MSG_DONTWAIT,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (n < 0) {
                if (closed_.load()) return;
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return;
            }
            if (closed_.load()) return;

            const Dur at = elapsedSinceStart();

            const unsigned char* p = buf.data();
            std::size_t len = static_cast<std::size_t>(n);

            // A raw IPv4 socket hands us the IP header too; the datagram socket
            // does not. Detect and skip it.
            if (family_ == Family::IP4 && len >= 20 && (p[0] >> 4) == 4) {
                std::size_t ihl = static_cast<std::size_t>(p[0] & 0x0f) * 4;
                if (ihl >= 20 && len > ihl) {
                    p += ihl;
                    len -= ihl;
                }
            }
            if (len < 8) continue;

            const int type = p[0];
            const int code = p[1];
            std::uint16_t seq = 0;
            Reply reply;
            reply.at = at;
            reply.responder = addrText(from);

            const bool echoReply =
                (family_ == Family::IP4) ? (type == ICMP_ECHOREPLY) : (type == ICMP6_ECHO_REPLY);
            const bool timeExceeded =
                (family_ == Family::IP4) ? (type == ICMP_TIME_EXCEEDED) : (type == ICMP6_TIME_EXCEEDED);
            const bool unreachable =
                (family_ == Family::IP4) ? (type == ICMP_DEST_UNREACH) : (type == ICMP6_DST_UNREACH);

            // A raw socket sees EVERY host ICMP packet, including replies belonging
            // to other processes, so the identifier must be checked as well as the
            // sequence: sequences restart at 1 in every process and would otherwise
            // collide. A datagram socket is demultiplexed by the kernel, which also
            // rewrites the identifier, so there it must be ignored
            // (codex HIGH finding).
            std::uint16_t id = 0;
            if (echoReply) {
                id = static_cast<std::uint16_t>(p[4] << 8 | p[5]);
                seq = static_cast<std::uint16_t>(p[6] << 8 | p[7]);
                if (isRaw_ && id != id_) continue;
                reply.outcome = Outcome::Reply;
            } else if (timeExceeded) {
                if (!quotedIdSeq(p + 8, len - 8, family_, id, seq)) continue;
                if (isRaw_ && id != id_) continue;
                reply.outcome = Outcome::TTLExpired;
            } else if (unreachable) {
                if (!quotedIdSeq(p + 8, len - 8, family_, id, seq)) continue;
                if (isRaw_ && id != id_) continue;
                reply.outcome = Outcome::Unreachable;
                reply.note = (family_ == Family::IP4) ? unreachNote4(code) : unreachNote6(code);
            } else {
                continue;
            }
            deliver(seq, reply);
        }
    }

    static std::string addrText(const sockaddr_storage& ss) {
        std::array<char, INET6_ADDRSTRLEN> buf{};
        if (ss.ss_family == AF_INET) {
            const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
            if (::inet_ntop(AF_INET, &a->sin_addr, buf.data(), buf.size())) return buf.data();
        } else if (ss.ss_family == AF_INET6) {
            const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
            if (::inet_ntop(AF_INET6, &a->sin6_addr, buf.data(), buf.size())) return buf.data();
        }
        return "";
    }

    std::string targetIp_;
    Family family_;
    // Atomic: the receiver reads it while close() clears it. A plain int here is a
    // data race, and descriptor reuse could make a concurrent send target an
    // unrelated socket (codex MEDIUM finding).
    std::atomic<int> fd_{-1};
    bool isRaw_ = false;
    sockaddr_storage dst_{};
    socklen_t dstLen_ = 0;

    std::uint16_t id_ = static_cast<std::uint16_t>(::getpid() & 0xffff);
    std::atomic<std::uint32_t> seq_{0};
    std::atomic<bool> closed_{false};

    std::mutex sendMu_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::map<std::uint16_t, Pending> pending_;

    std::thread receiver_;
};

}  // namespace

std::unique_ptr<Backend> makeRawBackend(const std::string& targetIp, RawSocketKind kind,
                                        std::string& err) {
    netInit();

    sockaddr_storage dst{};
    socklen_t dstLen = 0;
    Family family = Family::IP4;

    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, targetIp.c_str(), &v4) == 1) {
        auto* a = reinterpret_cast<sockaddr_in*>(&dst);
        a->sin_family = AF_INET;
        a->sin_addr = v4;
        dstLen = sizeof(sockaddr_in);
        family = Family::IP4;
    } else if (::inet_pton(AF_INET6, targetIp.c_str(), &v6) == 1) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&dst);
        a->sin6_family = AF_INET6;
        a->sin6_addr = v6;
        dstLen = sizeof(sockaddr_in6);
        family = Family::IP6;
    } else {
        err = "not an IP literal: " + targetIp;
        return nullptr;
    }

    // Opens exactly the socket kind asked for. It used to try SOCK_DGRAM and fall
    // back to SOCK_RAW internally, which hid the choice from detection -- and the
    // datagram socket is the one that needs checking (spec §6.2, cross-review R4).
    const int domain = (family == Family::IP4) ? AF_INET : AF_INET6;
    // The IPPROTO_* values live in two different anonymous enums in glibc's
    // <netinet/in.h>, so selecting between them in one conditional expression is a
    // deprecated enum-to-enum conversion. Casting first keeps the build warning-free.
    const int proto = (family == Family::IP4) ? static_cast<int>(IPPROTO_ICMP)
                                             : static_cast<int>(IPPROTO_ICMPV6);

    const bool isRaw = (kind == RawSocketKind::Raw);
    const int fd = ::socket(domain, isRaw ? SOCK_RAW : SOCK_DGRAM, proto);
    if (fd < 0) {
        err = isRaw ? std::string("SOCK_RAW: ") + std::strerror(errno) +
                          " (try setcap cap_net_raw+ep or run as root)"
                    : std::string("ICMP datagram socket: ") + std::strerror(errno) +
                          " (needs net.ipv4.ping_group_range to cover this gid)";
        return nullptr;
    }

    return std::make_unique<RawBackend>(targetIp, family, fd, isRaw, dst, dstLen);
}

}  // namespace netscope
