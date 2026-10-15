#include "ManagedSession.hpp"
#include <QDateTime>
#include <QRandomGenerator>
#include "ManagedRuntimePolicy.hpp"
#include "MihomoValidator.hpp"
#include "CoreOwnership.hpp"

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
        if (!startProfile(profile, groupId, executable, mixedPort, apiPort, readinessTimeoutMs, error)) return false;
        working = WorkingSnapshot{profile, metadata, executable, groupId, mixedPort, apiPort, readinessTimeoutMs};
        return true;
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
        lastReconnect = ReconnectOutcome::Rejected;
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
        return reconnectSnapshot(candidate, metadata, groupId, executable, mixedPort, apiPort, readinessTimeoutMs, error);
    }

    bool ManagedSession::reconnectSnapshot(const ManagedProfile &candidate, const SubscriptionMetadata &metadata,
                                           int groupId, const QString &executable, int mixedPort, int apiPort,
                                           int readinessTimeoutMs, QString &error) {
        error.clear();
        lastReconnect = ReconnectOutcome::Rejected;
        if (activeGroup != groupId || groupId < 0 || runtime.state() != ManagedCoreProcess::State::Ready ||
            runtime.processId() == 0 || readinessTimeoutMs < 1 || readinessTimeoutMs > 30000) {
            error = QStringLiteral("Reconnect requires the same ready group and a valid readiness timeout");
            return false;
        }
        if (metadata.expired(QDateTime::currentSecsSinceEpoch()) || metadata.exhausted()) {
            error = QStringLiteral("Managed subscription is expired or exhausted");
            return false;
        }
        ManagedProfile projected;
        // Preflight before Stop. Retain these exact candidate bytes, never reload
        // the store between stopping the old child and launching the replacement.
        if (!ManagedRuntimePolicy::projectLoopback(candidate, mixedPort, apiPort, QByteArray(64, 'a'), projected, error) ||
            !MihomoValidator::validate(executable, projected, error)) return false;
        // Validation can take time. Never intentionally stop a working child
        // for a candidate whose known subscription has expired meanwhile.
        if (metadata.expired(QDateTime::currentSecsSinceEpoch()) || metadata.exhausted()) {
            error = QStringLiteral("Managed subscription expired during reconnect preflight");
            return false;
        }
        const auto previous = working; // Retain exact last-Ready bytes, not latest store.
        if (!stop(error)) {
            lastReconnect = ReconnectOutcome::StopFailed;
            return false; // Forced/unconfirmed Stop must not restart or restore.
        }
        lastReconnect = ReconnectOutcome::Stopped;
        if (startProfile(candidate, groupId, executable, mixedPort, apiPort, readinessTimeoutMs, error)) {
            working = WorkingSnapshot{candidate, metadata, executable, groupId, mixedPort, apiPort, readinessTimeoutMs};
            lastReconnect = ReconnectOutcome::Applied;
            return true;
        }
        // At most one restore attempt, never while cleanup/ownership is uncertain.
        // Both old and freshly captured subscription constraints must allow use.
        const auto now = QDateTime::currentSecsSinceEpoch();
        if (!previous || runtime.processId() != 0 ||
            CoreOwnership::shared().owner() != CoreOwnership::Owner::None ||
            metadata.expired(now) || metadata.exhausted() ||
            previous->metadata.expired(now) || previous->metadata.exhausted()) return false;
        QString restoreError;
        if (startProfile(previous->profile, previous->groupId, previous->executable,
                         previous->mixedPort, previous->apiPort, previous->timeoutMs, restoreError)) {
            working = previous;
            lastReconnect = ReconnectOutcome::Restored;
            error = QStringLiteral("Replacement failed; previous managed session restored");
        } else {
            lastReconnect = ReconnectOutcome::RestoreFailed;
            error = QStringLiteral("Replacement and previous managed session restore failed");
        }
        return false; // Restored does NOT mean candidate applied successfully.
    }

    bool ManagedSession::stop(QString &error) {
        const bool graceful = stopSignal ? runtime.stop(stopSignal, error) : runtime.stop(error);
        if (runtime.processId() == 0) activeGroup = -1;
        if (runtime.processId() == 0) working.reset();
        return graceful;
    }

    bool ManagedSession::refreshAndReconnect(ManagedProfileStore &store, int groupId, const QUrl &url,
                                             const QString &appVersion, const QString &identityDirectory,
                                             const SubscriptionService::Fetcher &fetch, const QString &executable,
                                             int mixedPort, int apiPort, int readinessTimeoutMs, QString &error) {
        error.clear();
        lastReconnect = ReconnectOutcome::Rejected;
        if (groupId < 0 || activeGroup != groupId || runtime.state() != ManagedCoreProcess::State::Ready ||
            runtime.processId() == 0 || readinessTimeoutMs < 1 || readinessTimeoutMs > 30000) {
            error = QStringLiteral("Refresh/apply requires the same ready group and a valid readiness timeout");
            return false;
        }
        // Do not contact the panel/advertise a version before verifying its artifact.
        if (!MihomoValidator::verifyExecutable(executable, error)) return false;
        const auto validate = [&](const ManagedProfile &profile, QString &reason) {
            ManagedProfile projected;
            // Reject execution-policy failures BEFORE replacing the saved snapshot.
            return ManagedRuntimePolicy::projectLoopback(profile, mixedPort, apiPort, QByteArray(64, 'a'), projected, reason) &&
                   MihomoValidator::validate(executable, projected, reason);
        };
        SubscriptionService::CommittedSnapshot committed;
        if (!SubscriptionService::refresh(groupId, url, appVersion, identityDirectory, store, fetch, validate, error,
                                          nullptr, &committed))
            return false;
        return reconnectSnapshot(committed.profile, committed.metadata, groupId, executable,
                                 mixedPort, apiPort, readinessTimeoutMs, error);
    }
}
