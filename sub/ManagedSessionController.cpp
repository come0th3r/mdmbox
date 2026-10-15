#include "ManagedSessionController.hpp"

namespace NekoGui_sub {
    ManagedSessionController::ManagedSessionController(QObject *parent) : QObject(parent), worker(new QObject) {
        worker->moveToThread(&workerThread);
        connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
        workerThread.start();
    }

    ManagedSessionController::~ManagedSessionController() {
        // Wait for any bounded command already executing; never destroy a
        // QProcess from the UI thread or terminate a thread holding ownership.
        QMetaObject::invokeMethod(worker, [this] {
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
            emit statusChanged(static_cast<int>(state), group, pid);
            emit operationFinished(success, error);
        }, Qt::QueuedConnection);
    }

    bool ManagedSessionController::start(const QString &directory, int groupId, const QString &executable,
                                         int mixedPort, int apiPort, int timeoutMs) {
        if (pending) return false;
        pending = true;
        QMetaObject::invokeMethod(worker, [=] {
            if (!session) session = new ManagedSession;
            QString error;
            const bool success = session->start(ManagedProfileStore(directory), groupId, executable,
                                                 mixedPort, apiPort, timeoutMs, error);
            publish(success, error);
        }, Qt::QueuedConnection);
        return true;
    }

    bool ManagedSessionController::stop() {
        if (pending) return false;
        pending = true;
        QMetaObject::invokeMethod(worker, [this] {
            if (!session) session = new ManagedSession;
            QString error;
            const bool success = session->stop(error);
            publish(success, error);
        }, Qt::QueuedConnection);
        return true;
    }
}
