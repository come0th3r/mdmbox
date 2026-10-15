#include "../../sys/TrackedProcessCleanup.hpp"
#include "../../sub/LegacyCoreLifecycle.hpp"
#include <QCoreApplication>
#include <QTimer>
#include <QTextStream>
#include <list>
#include <memory>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    // No shell, network, inherited user config or unbounded orphan child.
    if (app.arguments().contains(QStringLiteral("--child"))) {
        QTimer::singleShot(10000, &app, &QCoreApplication::quit);
        return app.exec();
    }
    using Ownership = NekoGui_sub::CoreOwnership;
    using NekoGui_sub::LegacyCoreLifecycle;
    using NekoGui_sys::cleanupTrackedProcesses;
    using Processes = std::list<std::shared_ptr<QProcess>>;
    QString error;
    Processes tracked;
    int calls = 0;
    const auto refuse = [&](QProcess &) { ++calls; };
    if (!cleanupTrackedProcesses(tracked, refuse) || calls != 0) return 1;
    auto stopped = std::make_shared<QProcess>();
    tracked.push_back(stopped);
    if (!cleanupTrackedProcesses(tracked, refuse) || calls != 1) return 2;

    auto child = std::make_shared<QProcess>();
    child->setStandardOutputFile(QProcess::nullDevice());
    child->setStandardErrorFile(QProcess::nullDevice());
    child->start(QCoreApplication::applicationFilePath(), {QStringLiteral("--child")});
    if (!child->waitForStarted(3000)) return 3;
    const auto pid = child->processId();
    tracked.push_back(child);
    tracked.push_back(stopped); // An exited entry must not hide a live one.
    Ownership ownership;
    if (!ownership.acquire(Ownership::Owner::Legacy, error)) return 4;
    const bool cleaned = cleanupTrackedProcesses(tracked, refuse);
    if (cleaned || tracked.size() != 1 || tracked.front() != child || child->processId() != pid ||
        child->state() != QProcess::Running) return 5;
    if (LegacyCoreLifecycle::finishStop(ownership, true, cleaned, error) ||
        ownership.state() != Ownership::State::Uncertain || ownership.owner() != Ownership::Owner::Legacy ||
        ownership.acquire(Ownership::Owner::Managed, error)) return 6;
    QTextStream(stdout) << "TRACKED_LIVE_CHILD_REFUSAL_PASS\n";

    const auto kill = [](QProcess &process) {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished(3000);
        }
    };
    if (!cleanupTrackedProcesses(tracked, kill) || child->state() != QProcess::NotRunning ||
        child->processId() != 0) return 7;
    // Cleanup does not silently recover an already uncertain generation.
    if (LegacyCoreLifecycle::finishStop(ownership, true, true, error) ||
        ownership.state() != Ownership::State::Uncertain) return 8;
    QTextStream(stdout) << "TRACKED_CHILD_CONFIRMED_EXIT_PASS\n";

    // In the normal (never uncertain) path, real child cleanup permits switching.
    child->start(QCoreApplication::applicationFilePath(), {QStringLiteral("--child")});
    if (!child->waitForStarted(3000)) return 9;
    tracked.push_back(child);
    Ownership normal;
    if (!normal.acquire(Ownership::Owner::Legacy, error) ||
        !LegacyCoreLifecycle::finishStop(normal, true, cleanupTrackedProcesses(tracked, kill), error) ||
        !normal.acquire(Ownership::Owner::Managed, error)) return 10;
    tracked.push_back(nullptr);
    if (cleanupTrackedProcesses(tracked, kill) || tracked.size() != 1) return 11;
    QTextStream(stdout) << "TRACKED_CHILD_NORMAL_SWITCH_PASS\n";
    return 0;
}
