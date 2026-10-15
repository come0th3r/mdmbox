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
        explicit ManagedSessionController(QObject *parent = nullptr);
        ~ManagedSessionController() override;
        bool start(const QString &directory, int groupId, const QString &executable,
                   int mixedPort, int apiPort, int timeoutMs);
        bool stop();
        bool busy() const { return pending; }
        int state() const { return lastState; }
        int groupId() const { return lastGroup; }
        qint64 processId() const { return lastPid; }
        QJsonObject snapshot() const;
    signals:
        // int is ManagedCoreProcess::State; Ready is NOT VPN connected.
        void statusChanged(int state, int groupId, qint64 processId);
        void operationFinished(bool success, const QString &error);
        void runtimeFailed(const QString &error);
    private:
        QThread workerThread;
        QObject *worker;
        ManagedSession *session = nullptr; // Access only on workerThread.
        QTimer *monitor = nullptr; // Worker-owned.
        bool executing = false; // Worker-only; protects nested readiness loops.
        bool pending = false;
        int lastState = static_cast<int>(ManagedCoreProcess::State::Stopped);
        int lastGroup = -1;
        qint64 lastPid = 0;
        void publish(bool success, const QString &error);
        void ensureSession();
    };
}
