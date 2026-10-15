#pragma once

#include "CoreOwnership.hpp"

namespace NekoGui_sub {
    // Result policy shared by production stop and isolated fault fixtures.
    // A reply from a restarted daemon cannot resolve an earlier uncertainty.
    class LegacyCoreLifecycle {
    public:
        static bool finishStop(CoreOwnership &ownership, bool rpcSucceeded,
                               bool externalProcessesStopped, QString &error, quint64 generation = 0) {
            return ownership.finishStop(CoreOwnership::Owner::Legacy,
                                        rpcSucceeded && externalProcessesStopped, error, generation);
        }
    };
}
