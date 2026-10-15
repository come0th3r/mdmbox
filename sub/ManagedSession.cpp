#include "ManagedSession.hpp"
#include <QDateTime>
#include <QRandomGenerator>
#include "ManagedRuntimePolicy.hpp"
#include "MihomoValidator.hpp"

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
        return startProfile(profile, groupId, executable, mixedPort, apiPort, readinessTimeoutMs, error);
    }

    bool ManagedSession::startProfile(const ManagedProfile &profile, int groupId, const QString &executable,
                                      int mixedPort, int apiPort, int readinessTimeoutMs, QString &error) {
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

    bool ManagedSession::reconnect(const ManagedProfileStore &store, int groupId, const QString &executable,
                                   int mixedPort, int apiPort, int readinessTimeoutMs, QString &error) {
        error.clear();
        if (activeGroup != groupId || groupId < 0 || runtime.state() != ManagedCoreProcess::State::Ready ||
            runtime.processId() == 0) {
            error = QStringLiteral("Reconnect requires the same active ready managed group");
            return false;
        }
        if (readinessTimeoutMs < 1 || readinessTimeoutMs > 30000) {
            error = QStringLiteral("Managed readiness timeout must be 1..30000 ms");
            return false;
        }
        ManagedProfile candidate;
        SubscriptionMetadata metadata;
        if (!store.loadSnapshot(groupId, candidate, metadata, error)) return false;
        if (metadata.expired(QDateTime::currentSecsSinceEpoch()) || metadata.exhausted()) {
            error = QStringLiteral("Managed subscription is expired or exhausted");
            return false;
        }
        ManagedProfile projected;
        // Preflight before Stop. Retain these exact candidate bytes, never reload
        // the store between stopping the old child and launching the replacement.
        if (!ManagedRuntimePolicy::projectLoopback(candidate, mixedPort, apiPort, QByteArray(64, 'a'), projected, error) ||
            !MihomoValidator::validate(executable, projected, error)) return false;
        if (!stop(error)) return false; // Forced/unconfirmed Stop must not restart.
        // No automatic rollback/retry if replacement launch/readiness fails.
        return startProfile(candidate, groupId, executable, mixedPort, apiPort, readinessTimeoutMs, error);
    }

    bool ManagedSession::stop(QString &error) {
        const bool graceful = runtime.stop(error);
        if (runtime.processId() == 0) activeGroup = -1;
        return graceful;
    }
}
