#include "ManagedSessionController.hpp"

namespace NekoGui_sub {
    QJsonObject ManagedSessionController::snapshot() const {
        QString stateName;
        switch (static_cast<ManagedCoreProcess::State>(lastState)) {
        case ManagedCoreProcess::State::Stopped: stateName = QStringLiteral("stopped"); break;
        case ManagedCoreProcess::State::Starting: stateName = QStringLiteral("starting"); break;
        case ManagedCoreProcess::State::Running: stateName = QStringLiteral("running"); break;
        case ManagedCoreProcess::State::Ready: stateName = QStringLiteral("ready"); break;
        case ManagedCoreProcess::State::Stopping: stateName = QStringLiteral("stopping"); break;
        case ManagedCoreProcess::State::Failed: stateName = QStringLiteral("failed"); break;
        }
        return {{QStringLiteral("schemaVersion"), 1},
                {QStringLiteral("available"), true},
                {QStringLiteral("scope"), QStringLiteral("loopback-only")},
                {QStringLiteral("state"), stateName},
                {QStringLiteral("busy"), pending},
                {QStringLiteral("groupId"), lastGroup},
                {QStringLiteral("controllerReady"), !pending && lastState == static_cast<int>(ManagedCoreProcess::State::Ready)},
                {QStringLiteral("vpnConnected"), false}};
    }

    ManagedSessionController::ManagedSessionController(QObject *parent) : QObject(parent), worker(new QObject) {
        worker->moveToThread(&workerThread);
        connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
        workerThread.start();
    }

    ManagedSessionController::~ManagedSessionController() {
        // Wait for any bounded command already executing; never destroy a
        // QProcess from the UI thread or terminate a thread holding ownership.
        QMetaObject::invokeMethod(worker, [this] {
            if (monitor) monitor->stop();
            if (session) {
                QString ignored;
                session->stop(ignored);
                delete session;
                session = nullptr;
            }
        }, Qt::BlockingQueuedConnection);
        workerThread.quit();
        workerThread.wait();
    }

    void ManagedSessionController::publish(bool success, const QString &error) {
        const auto state = session->state();
        const auto group = session->groupId();
        const auto pid = session->processId();
        QMetaObject::invokeMethod(this, [this, state, group, pid, success, error] {
            pending = false;
            lastState = static_cast<int>(state);
            lastGroup = group;
            lastPid = pid;
            emit statusChanged(lastState, group, pid);
            emit operationFinished(success, error);
        }, Qt::QueuedConnection);
    }

    void ManagedSessionController::ensureSession() {
        if (session) return;
        session = new ManagedSession;
        monitor = new QTimer(worker);
        monitor->setInterval(100);
        connect(monitor, &QTimer::timeout, worker, [this] {
            if (executing || session->groupId() < 0 ||
                session->state() != ManagedCoreProcess::State::Failed) return;
            executing = true;
            QString ignored;
            session->stop(ignored);
            const auto group = session->groupId();
            const auto pid = session->processId();
            // Report once; do not loop stop attempts on an unconfirmed cleanup.
            monitor->stop();
            executing = false;
            QMetaObject::invokeMethod(this, [this, group, pid] {
                lastState = static_cast<int>(ManagedCoreProcess::State::Failed);
                lastGroup = group;
                lastPid = pid;
                emit statusChanged(lastState, group, pid);
                emit runtimeFailed(QStringLiteral("Managed core exited unexpectedly"));
            }, Qt::QueuedConnection);
        });
    }

    bool ManagedSessionController::start(const QString &directory, int groupId, const QString &executable,
                                         int mixedPort, int apiPort, int timeoutMs) {
        if (pending) return false;
        pending = true;
        QMetaObject::invokeMethod(worker, [=] {
            ensureSession();
            executing = true;
            QString error;
            const bool success = session->start(ManagedProfileStore(directory), groupId, executable,
                                                 mixedPort, apiPort, timeoutMs, error);
            executing = false;
            if (success) monitor->start();
            publish(success, error);
        }, Qt::QueuedConnection);
        return true;
    }

    bool ManagedSessionController::reconnect(const QString &directory, int groupId, const QString &executable,
                                            int mixedPort, int apiPort, int timeoutMs) {
        if (pending) return false;
        pending = true;
        QMetaObject::invokeMethod(worker, [=] {
            ensureSession();
            executing = true;
            QString error;
            const bool success = session->reconnect(ManagedProfileStore(directory), groupId, executable,
                                                    mixedPort, apiPort, timeoutMs, error);
            executing = false;
            // A preflight refusal may leave the old Ready session active.
            if (session->groupId() >= 0) monitor->start();
            publish(success, error);
        }, Qt::QueuedConnection);
        return true;
    }

    bool ManagedSessionController::stop() {
        if (pending) return false;
        pending = true;
        QMetaObject::invokeMethod(worker, [this] {
            ensureSession();
            executing = true;
            monitor->stop();
            QString error;
            const bool success = session->stop(error);
            executing = false;
            publish(success, error);
        }, Qt::QueuedConnection);
        return true;
    }
}
