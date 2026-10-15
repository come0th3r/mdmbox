#pragma once
#include <QByteArray>

namespace NekoGui_sub {
    // One bounded synchronous loopback request; no process ownership or VPN claim.
    class ManagedControllerProbe {
    public:
        enum class Result { Accepted, Retry, Rejected };
        static Result version(int port, const QByteArray &token, int timeoutMs);
    };
}
