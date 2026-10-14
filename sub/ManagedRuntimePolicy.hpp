#pragma once

#include "ManagedProfile.hpp"

namespace NekoGui_sub {
    // Conservative gate for the first loopback-only runtime. Does not authorize OS changes.
    class ManagedRuntimePolicy {
    public:
        static bool checkSelfContained(const ManagedProfile &profile, QString &error);
    };
}
