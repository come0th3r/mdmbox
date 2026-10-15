#pragma once

#include "ManagedCoreProcess.hpp"
#include "ManagedProfileStore.hpp"
#include <optional>

namespace NekoGui_sub {
    // Worker-thread-only session over the existing group-keyed snapshot store.
    // Ready is authenticated loopback readiness, never a VPN-connected claim.
    class ManagedSession {
    public:
        enum class ReconnectOutcome { None, Rejected, Applied, Stopped, Restored, RestoreFailed };
        ReconnectOutcome reconnectOutcome() const { return lastReconnect; }
        bool start(const ManagedProfileStore &store, int groupId, const QString &executable,
                   int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        bool stop(QString &error);
        bool reconnect(const ManagedProfileStore &store, int groupId, const QString &executable,
                       int mixedPort, int apiPort, int readinessTimeoutMs, QString &error);
        int groupId() const { return activeGroup; }
        ManagedCoreProcess::State state() const { return runtime.state(); }
        qint64 processId() const { return runtime.processId(); }
    private:
        ManagedCoreProcess runtime;
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
    };
}
