#pragma once

#include "ManagedCoreProcess.hpp"
#include "ManagedProfileStore.hpp"
#include "SubscriptionService.hpp"
#include <optional>
#include <utility>

namespace NekoGui_sub {
    // Worker-thread-only session over the existing group-keyed snapshot store.
    // Ready is authenticated loopback readiness, never a VPN-connected claim.
    class ManagedSession {
    public:
        enum class ReconnectOutcome { None, Rejected, Applied, Stopped, Restored, RestoreFailed, StopFailed };
        ManagedSession() = default;
        // Same bounded, child-specific signal contract as ManagedCoreProcess.
        explicit ManagedSession(ManagedCoreProcess::StopSignal signal) : stopSignal(std::move(signal)) {}
        ReconnectOutcome reconnectOutcome() const { return lastReconnect; }
        bool start(const ManagedProfileStore &store, int groupId, const QString &executable,
                   int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        bool stop(QString &error);
        bool reconnect(const ManagedProfileStore &store, int groupId, const QString &executable,
                        int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        // Explicit worker-only refresh/apply; fetch is production HTTPS or a test fixture.
        // False may leave a newly stored candidate; inspect outcome for runtime restore.
        bool refreshAndReconnect(ManagedProfileStore &store, int groupId, const QUrl &url,
                                 const QString &appVersion, const QString &identityDirectory,
                                 const SubscriptionService::Fetcher &fetch, const QString &executable,
                                 int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        int groupId() const { return activeGroup; }
        ManagedCoreProcess::State state() const { return runtime.state(); }
        qint64 processId() const { return runtime.processId(); }
    private:
        ManagedCoreProcess runtime;
        ManagedCoreProcess::StopSignal stopSignal;
        int activeGroup = -1;
        struct WorkingSnapshot {
            ManagedProfile profile;
            SubscriptionMetadata metadata;
            QString executable;
            int groupId, mixedPort, apiPort, timeoutMs;
        };
        std::optional<WorkingSnapshot> working;
        ReconnectOutcome lastReconnect = ReconnectOutcome::None;
        bool startProfile(const ManagedProfile &profile, int groupId, const QString &executable,
                           int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        bool reconnectSnapshot(const ManagedProfile &candidate, const SubscriptionMetadata &metadata,
                               int groupId, const QString &executable, int mixedPort, int apiPort,
                               int readinessTimeoutMs, QString &error);
    };
}
