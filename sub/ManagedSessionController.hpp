#pragma once

#include <QObject>
#include <QThread>
#include <QTimer>
#include <QJsonObject>
#include "ManagedSession.hpp"

namespace NekoGui_sub {
    // Public methods and destruction must run on this object's owner thread.
    // Serializes commands; worker creates/destroys all QProcess state itself.
    class ManagedSessionController : public QObject {
        Q_OBJECT
    public:
        explicit ManagedSessionController(QObject *parent = nullptr,
                                          ManagedCoreProcess::StopSignal stopSignal = {});
        ~ManagedSessionController() override;
        bool start(const QString &directory, int groupId, const QString &executable,
                   int mixedPort, int apiPort, int timeoutMs);
        bool stop();
        bool reconnect(const QString &directory, int groupId, const QString &executable,
                       int mixedPort, int apiPort, int timeoutMs, const QString &requestId = {});
        bool refreshAndReconnect(const QString &directory, int groupId, const QUrl &url,
                                 const QString &appVersion, const QString &executable,
                                 int mixedPort, int apiPort, int timeoutMs, const QString &requestId);
        bool busy() const { return pending || deliveringCompletion; }
        int state() const { return lastState; }
        int groupId() const { return lastGroup; }
        qint64 processId() const { return lastPid; }
        QJsonObject snapshot() const;
    signals:
        // int is ManagedCoreProcess::State; Ready is NOT VPN connected.
        void statusChanged(int state, int groupId, qint64 processId);
        void operationFinished(bool success, const QString &error);
        void runtimeFailed(const QString &error);
        // Compatibility notification, emitted before operationFinished.
        void reconnectFinished(int outcome); // ManagedSession::ReconnectOutcome.
        // One immutable completion per accepted reconnect; busy refusals emit none.
        void reconnectCompleted(const QString &requestId, bool success, int outcome,
                                const QString &error, const QJsonObject &snapshot);
        void refreshCompleted(const QString &requestId, bool success, int outcome,
                              const QString &error, const QJsonObject &snapshot);
    private:
        QThread workerThread;
        QObject *worker;
        ManagedSession *session = nullptr; // Access only on workerThread.
        ManagedCoreProcess::StopSignal stopSignal; // Optional bounded child-specific adapter.
        QTimer *monitor = nullptr; // Worker-owned.
        bool executing = false; // Worker-only; protects nested readiness loops.
        bool pending = false;
        bool deliveringCompletion = false; // Owner thread; reject reentrant commands during notifications.
        int lastState = static_cast<int>(ManagedCoreProcess::State::Stopped);
        int lastGroup = -1;
        qint64 lastPid = 0;
        void publish(bool success, const QString &error,
                      ManagedSession::ReconnectOutcome outcome = ManagedSession::ReconnectOutcome::None,
                      const QString &requestId = {}, bool refresh = false);
        void ensureSession();
    };
}
