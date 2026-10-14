#pragma once

#include "ManagedProfile.hpp"

namespace NekoGui_sub {
    // Synchronous: invoke on a service worker, never the GUI thread.
    class MihomoValidator {
    public:
        static bool validate(const QString &executable, const ManagedProfile &profile, QString &error);
    };
}
