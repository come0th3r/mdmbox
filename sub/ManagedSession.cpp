#include "ManagedSession.hpp"
#include <QDateTime>
#include <QRandomGenerator>

namespace NekoGui_sub {
    bool ManagedSession::start(const ManagedProfileStore &store, int groupId, const QString &executable,
                               int mixedPort, int apiPort, int readinessTimeoutMs, QString &error) {
        error.clear();
        if (activeGroup >= 0 || runtime.processId() != 0) {
            error = QStringLiteral("Managed session already owns a group; stop it before switching");
            return false;
        }
        if (readinessTimeoutMs < 1 || readinessTimeoutMs > 30000) {
            error = QStringLiteral("Managed readiness timeout must be 1..30000 ms");
            return false;
        }
        ManagedProfile profile;
        SubscriptionMetadata metadata;
        if (!store.loadSnapshot(groupId, profile, metadata, error)) return false;
        if (metadata.expired(QDateTime::currentSecsSinceEpoch()) || metadata.exhausted()) {
            error = QStringLiteral("Managed subscription is expired or exhausted");
            return false;
        }
        QByteArray token;
        for (int i = 0; i < 8; ++i)
            token += QByteArray::number(QRandomGenerator::system()->generate(), 16).rightJustified(8, '0');
        if (!runtime.start(executable, profile, mixedPort, apiPort, token, error)) return false;
        activeGroup = groupId;
        if (!runtime.waitReady(readinessTimeoutMs, error)) {
            // Retain the group if cleanup could not confirm exit.
            if (runtime.processId() == 0) activeGroup = -1;
            return false;
        }
        return true;
    }

    bool ManagedSession::stop(QString &error) {
        const bool graceful = runtime.stop(error);
        if (runtime.processId() == 0) activeGroup = -1;
        return graceful;
    }
}
