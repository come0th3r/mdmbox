#pragma once

#include "ManagedProfile.hpp"

namespace NekoGui_sub {
    // Conservative gate for the first loopback-only runtime. Does not authorize OS changes.
    class ManagedRuntimePolicy {
    public:
        static bool checkSelfContained(const ManagedProfile &profile, QString &error);
        // Detached loopback-only projection. Caller supplies a fresh API token; no execution here.
        static bool projectLoopback(const ManagedProfile &profile, int mixedPort, int controllerPort,
                                    const QByteArray &apiToken, ManagedProfile &result, QString &error);
    };
}
