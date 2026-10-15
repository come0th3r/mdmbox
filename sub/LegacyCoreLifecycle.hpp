#pragma once

#include "CoreOwnership.hpp"

namespace NekoGui_sub {
    // Result policy shared by production stop and isolated fault fixtures.
    // A reply from a restarted daemon cannot resolve an earlier uncertainty.
    class LegacyCoreLifecycle {
    public:
        static bool finishStop(CoreOwnership &ownership, bool rpcSucceeded,
                               bool externalProcessesStopped, QString &error) {
            if (ownership.owner() != CoreOwnership::Owner::Legacy) {
                error = QStringLiteral("Legacy stop does not own the runtime");
                return false;
            }
            if (!rpcSucceeded || !externalProcessesStopped ||
                ownership.state() == CoreOwnership::State::Uncertain) {
                QString ignored;
                ownership.markUncertain(CoreOwnership::Owner::Legacy, ignored);
                error = QStringLiteral("Legacy shutdown is unconfirmed; restart the application");
                return false;
            }
            return ownership.release(CoreOwnership::Owner::Legacy, error);
        }
    };
}
