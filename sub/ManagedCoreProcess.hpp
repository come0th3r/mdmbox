#pragma once

#include "ManagedProfile.hpp"
#include <QProcess>
#include <QTemporaryDir>
#include <functional>
#include <memory>

namespace NekoGui_sub {
    // Synchronous, single-worker-thread owner; do not reenter during waitReady.
    // Running means alive; Ready means controller verified, NOT VPN connected.
    class ManagedCoreProcess {
    public:
        enum class State { Stopped, Starting, Running, Ready, Stopping, Failed };
        using StopSignal = std::function<bool(qint64)>;
        ~ManagedCoreProcess();
        bool start(const QString &executable, const ManagedProfile &panel, int mixedPort, int apiPort,
                   const QByteArray &apiToken, QString &error);
        // Authenticated controller readiness only, NOT VPN data-path readiness.
        // Invalid timeout leaves the process untouched; failed probes clean up.
        bool waitReady(int timeoutMs, QString &error);
        // Signal adapter must be bounded and target only this child's isolated console.
        // False after forced cleanup: do not report a graceful stop.
        bool stop(const StopSignal &signal, QString &error);
        // Default platform adapter; Windows helper must be beside the application.
        bool stop(QString &error);
        State state() const;
        qint64 processId() const;

    private:
        bool ownsRuntime = false;
        QProcess process;
        std::unique_ptr<QTemporaryDir> home;
        State current = State::Stopped;
        int controllerPort = 0;
        QByteArray controllerToken;
        bool forceCleanup();
    };
}
