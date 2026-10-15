#include "../../sys/ProcessCleanupCompletion.hpp"
#include "../../sub/LegacyCoreLifecycle.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>
#include <QTextStream>
#include <memory>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    using Completion = NekoGui_sys::ProcessCleanupCompletion;
    using Ownership = NekoGui_sub::CoreOwnership;
    QThread thread;
    QObject worker;
    worker.moveToThread(&thread);
    thread.start();
    int result = 0;
    const auto run = [&]() -> int {
        for (const bool success : {false, true}) {
            auto completion = std::make_shared<Completion>();
            QMetaObject::invokeMethod(&worker, [completion, success] { completion->complete(success); }, Qt::QueuedConnection);
            if (completion->wait(3000) != success) return 1;
        }
        // Occupy the worker queue until the caller has actually timed out.
        auto completion = std::make_shared<Completion>();
        auto gate = std::make_shared<QSemaphore>();
        auto delivered = std::make_shared<QSemaphore>();
        QMetaObject::invokeMethod(&worker, [completion, gate, delivered] {
            // Bounded even if the test fails before releasing the gate.
            if (gate->tryAcquire(1, 3000)) completion->complete(true);
            delivered->release();
        }, Qt::QueuedConnection);
        Ownership ownership;
        QString error;
        if (!ownership.acquire(Ownership::Owner::Legacy, error)) return 2;
        QElapsedTimer timer;
        timer.start();
        const bool stopped = completion->wait(30);
        if (stopped || timer.elapsed() > 2000 ||
            NekoGui_sub::LegacyCoreLifecycle::finishStop(ownership, true, stopped, error)) return 3;
        std::weak_ptr<Completion> weak = completion;
        completion.reset(); // The late callback must own its result safely.
        gate->release();
        if (!delivered->tryAcquire(1, 3000)) return 4;
        if (auto late = weak.lock()) {
            if (late->wait(0)) return 5;
        }
        if (ownership.state() != Ownership::State::Uncertain ||
            ownership.acquire(Ownership::Owner::Managed, error) ||
            NekoGui_sub::LegacyCoreLifecycle::finishStop(ownership, true, true, error)) return 6;
        Completion missing;
        if (missing.wait(1)) return 7;
        missing.complete(true);
        if (missing.wait(0)) return 8;
        Completion failed;
        failed.complete(false);
        failed.complete(true); // Duplicate callback cannot overwrite failure.
        if (failed.wait(0)) return 9;
        Completion invalid;
        if (invalid.wait(-1)) return 10;
        invalid.complete(true);
        if (invalid.wait(0)) return 11;
        QTextStream(stdout) << "CLEANUP_QUEUE_SUCCESS_FAILURE_TIMEOUT_LATE_REPLY_PASS\n";
        return 0;
    };
    result = run();
    // Drain callbacks and return QObject affinity before destroying the worker.
    QMetaObject::invokeMethod(&worker, [&worker, &app] { worker.moveToThread(app.thread()); }, Qt::BlockingQueuedConnection);
    thread.quit();
    thread.wait();
    return result;
}
