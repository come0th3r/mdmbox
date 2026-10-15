#pragma once

#include <QString>

namespace NekoGui_sub {
    struct ManagedLaunchPolicy {
        // Disabling a mode must remain possible even during failed cleanup.
        static bool allowLegacyOperation(bool enabling, bool pending, bool activeGroup,
                                         bool liveProcess, bool managedOwner) {
            return !enabling || !(pending || activeGroup || liveProcess || managedOwner);
        }
        static bool allow(bool groupExists, bool archived, const QString &kind,
                          bool systemProxy, bool tun, bool legacyActive, bool exiting,
                          QString &error) {
            error.clear();
            if (exiting) error = QStringLiteral("Application shutdown is in progress");
            else if (!groupExists || archived || kind != QStringLiteral("mihomo-full"))
                error = QStringLiteral("An active mihomo-full group is required");
            else if (systemProxy || tun || legacyActive)
                error = QStringLiteral("Loopback managed start requires legacy, TUN and system proxy to be stopped");
            return error.isEmpty();
        }
    };
}
