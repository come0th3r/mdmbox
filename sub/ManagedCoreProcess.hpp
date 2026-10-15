#pragma once

#include "ManagedProfile.hpp"
#include <QProcess>
#include <QTemporaryDir>
#include <functional>
#include <memory>

namespace NekoGui_sub {
    // Synchronous, single-worker-thread owner. Running means alive, NOT connected/ready.
    class ManagedCoreProcess {
    public:
        enum class State { Stopped, Starting, Running, Stopping, Failed };
        using StopSignal = std::function<bool(qint64)>;
        ~ManagedCoreProcess();
        bool start(const QString &executable, const ManagedProfile &panel, int mixedPort, int apiPort,
                   const QByteArray &apiToken, QString &error);
        // Signal adapter must be bounded and target only this child's isolated console.
        // False after forced cleanup: do not report a graceful stop.
        bool stop(const StopSignal &signal, QString &error);
        State state() const;
        qint64 processId() const;

    private:
        QProcess process;
        std::unique_ptr<QTemporaryDir> home;
        State current = State::Stopped;
        bool forceCleanup();
    };
}
