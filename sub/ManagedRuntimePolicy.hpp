#pragma once

#include "ManagedProfile.hpp"

namespace NekoGui_sub {
    // Explicit runtime-only rule layers. They are applied to a detached
    // projection and never written back into the panel snapshot.
    struct ManagedRuntimeRuleOverrides {
        QStringList technicalRules;
        QStringList localRules;
    };

    // Conservative gate for the first loopback-only runtime. Does not authorize OS changes.
    class ManagedRuntimePolicy {
    public:
        static bool checkSelfContained(const ManagedProfile &profile, QString &error);
        // Detached loopback-only projection. Caller supplies a fresh API token; no execution here.
        static bool projectLoopback(const ManagedProfile &profile, int mixedPort, int controllerPort,
                                    const QByteArray &apiToken, ManagedProfile &result, QString &error);
        // Rule priority: technical rules, local overrides, then panel rules
        // byte-for-byte in their existing order (including its terminal rule).
        static bool projectLoopback(const ManagedProfile &profile, int mixedPort, int controllerPort,
                                    const QByteArray &apiToken, const ManagedRuntimeRuleOverrides &overrides,
                                    ManagedProfile &result, QString &error);
    };
}
