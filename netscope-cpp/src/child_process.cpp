#include "child_process.h"

#include <array>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace netscope {

ChildProcess::~ChildProcess() {
    kill();
    wait();
}

#ifdef _WIN32

namespace {

// Quotes one argument per the CommandLineToArgvW rules, so a path with spaces
// survives the round trip through the single command-line string Windows uses.
std::string quoteArg(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\"") == std::string::npos) return arg;
    std::string out = "\"";
    std::size_t backslashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }
        if (c == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out += '"';
            backslashes = 0;
            continue;
        }
        out.append(backslashes, '\\');
        backslashes = 0;
        out += c;
    }
    out.append(backslashes * 2, '\\');
    out += '"';
    return out;
}

}  // namespace

bool ChildProcess::start(const std::vector<std::string>& argv,
                         const std::vector<std::string>& /*env*/) {
    std::lock_guard<std::mutex> lk(mu_);
    if (argv.empty()) return false;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readEnd = nullptr;
    HANDLE writeEnd = nullptr;
    if (::CreatePipe(&readEnd, &writeEnd, &sa, 64 * 1024) == FALSE) return false;
    // The read end must not be inherited, or the child would hold it open and we
    // would never see EOF.
    ::SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    std::string cmdline;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        if (i > 0) cmdline += ' ';
        cmdline += quoteArg(argv[i]);
    }

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // never flash a console over the TUI
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back('\0');

    const BOOL ok = ::CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                                     CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    ::CloseHandle(writeEnd);
    if (ok == FALSE) {
        ::CloseHandle(readEnd);
        return false;
    }
    ::CloseHandle(pi.hThread);

    process_ = pi.hProcess;
    readPipe_ = readEnd;
    killed_.store(false);
    running_.store(true);
    return true;
}

void ChildProcess::readAll(std::string& out) {
    HANDLE pipe = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        pipe = static_cast<HANDLE>(readPipe_);
    }
    if (pipe == nullptr) return;

    std::array<char, 4096> buf{};
    for (;;) {
        DWORD read = 0;
        if (::ReadFile(pipe, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) == FALSE) {
            break;  // pipe closed, by the child exiting or by kill()
        }
        if (read == 0) break;
        out.append(buf.data(), read);
        if (out.size() > 1u << 20) break;  // a sane ceiling on tool output
    }
}

void ChildProcess::wait() {
    std::lock_guard<std::mutex> lk(mu_);
    if (process_ != nullptr) {
        ::WaitForSingleObject(static_cast<HANDLE>(process_), 5000);
    }
    closeHandles();
    running_.store(false);
}

void ChildProcess::kill() {
    std::lock_guard<std::mutex> lk(mu_);
    killed_.store(true);
    if (process_ != nullptr && running_.load()) {
        ::TerminateProcess(static_cast<HANDLE>(process_), 1);
    }
    // Closing the read end makes an in-progress ReadFile fail immediately.
    if (readPipe_ != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(readPipe_));
        readPipe_ = nullptr;
    }
}

void ChildProcess::closeHandles() {
    if (process_ != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(process_));
        process_ = nullptr;
    }
    if (readPipe_ != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(readPipe_));
        readPipe_ = nullptr;
    }
}

#else  // POSIX

bool ChildProcess::start(const std::vector<std::string>& argv,
                         const std::vector<std::string>& env) {
    std::lock_guard<std::mutex> lk(mu_);
    if (argv.empty()) return false;

    int fds[2];
    if (::pipe(fds) != 0) return false;

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        return false;
    }

    if (pid == 0) {
        // Child. Only async-signal-safe work here.
        ::close(fds[0]);
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[1]);

        for (const std::string& kv : env) {
            const auto eq = kv.find('=');
            if (eq == std::string::npos) continue;
            ::setenv(kv.substr(0, eq).c_str(), kv.substr(eq + 1).c_str(), 1);
        }

        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const std::string& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);

        ::execvp(args[0], args.data());
        ::_exit(127);  // exec failed; the parent sees EOF and an exit status
    }

    ::close(fds[1]);
    pid_ = pid;
    fd_ = fds[0];
    killed_.store(false);
    running_.store(true);
    return true;
}

void ChildProcess::readAll(std::string& out) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(mu_);
        fd = fd_;
    }
    if (fd < 0) return;

    std::array<char, 4096> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out.append(buf.data(), static_cast<std::size_t>(n));
        if (out.size() > 1u << 20) break;
    }
}

void ChildProcess::wait() {
    std::lock_guard<std::mutex> lk(mu_);
    if (pid_ > 0) {
        int status = 0;
        ::waitpid(pid_, &status, 0);
        pid_ = -1;
    }
    closeHandles();
    running_.store(false);
}

void ChildProcess::kill() {
    std::lock_guard<std::mutex> lk(mu_);
    killed_.store(true);
    if (pid_ > 0 && running_.load()) {
        ::kill(pid_, SIGKILL);
    }
    // Closing the read end makes an in-progress read return 0.
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void ChildProcess::closeHandles() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

#endif

}  // namespace netscope
