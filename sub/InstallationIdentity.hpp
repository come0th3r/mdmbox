#pragma once

#include <QString>

namespace NekoGui_sub {
    class InstallationIdentity {
    public:
        // The directory belongs to this application's data, not the machine registry.
        static bool loadOrCreate(const QString &directory, QString &identity, QString &error);
    };
}
