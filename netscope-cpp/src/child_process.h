// A child process whose output we capture and whose lifetime we can end.
//
// popen() is not usable here: it gives no handle to the child, so a wedged
// tracert cannot be terminated and shutdown() would block on an unbounded
// fgets/pclose. A 30-hop sweep with a 2s per-probe wait can legitimately run for
// minutes, and the teardown contract in docs/netscope-spec.md §3.3 requires a
// bounded drain. This wrapper keeps the process handle so close() can kill it
// (codex HIGH finding).
#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace netscope {

class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess();

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    // Spawns argv[0] with the remaining elements as arguments, capturing stdout and
    // stderr together. Returns false if the process could not be started.
    //
    // On POSIX, env entries of the form "K=V" are added to the child's environment.
    // On Windows they are ignored: the parsers there are locale-agnostic by design
    // (see probe_parse.h), so there is nothing to force.
    bool start(const std::vector<std::string>& argv, const std::vector<std::string>& env);

    // Reads until EOF or until kill() is called. Appends to out.
    void readAll(std::string& out);

    // Waits for exit and releases the handle. Safe to call more than once.
    void wait();

    // Terminates the child if it is still running and closes the pipe, which makes
    // an in-progress readAll return promptly.
    void kill();

    bool running() const { return running_.load(); }

private:
    void closeHandles();

    std::mutex mu_;
    std::atomic<bool> running_{false};
    std::atomic<bool> killed_{false};

#ifdef _WIN32
    void* process_ = nullptr;  // HANDLE
    void* readPipe_ = nullptr; // HANDLE
#else
    int pid_ = -1;
    int fd_ = -1;
#endif
};

}  // namespace netscope
