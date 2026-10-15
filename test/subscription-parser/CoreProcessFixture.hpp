#pragma once

#include "sys/ExternalProcess.hpp"
#include "main/NekoGui.hpp"
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>
#include <QTextStream>

inline bool runCoreProcessFixture() {
    struct Restore {
        std::function<void(QString, QString)> callback = MW_dialog_message;
        bool coreRunning = NekoGui::dataStore->core_running;
        bool exiting = NekoGui::dataStore->prepare_exit;
        ~Restore() {
            MW_dialog_message = callback;
            NekoGui::dataStore->core_running = coreRunning;
            NekoGui::dataStore->prepare_exit = exiting;
        }
    } restore;
    const auto until = [](const std::function<bool()> &predicate, int timeout) {
        QElapsedTimer timer;
        timer.start();
        while (!predicate() && timer.elapsed() < timeout) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(1);
        }
        return predicate();
    };
    QStringList events;
    MW_dialog_message = [&](QString sender, QString info) {
        if (sender == "ExternalProcess") events.append(info);
    };
    using Ownership = NekoGui_sub::CoreOwnership;
    auto &ownership = Ownership::shared();
    QString error;
    quint64 owned = 0;
    if (!ownership.acquire(Ownership::Owner::Legacy, error, &owned)) return false;
    struct Release {
        quint64 generation;
        ~Release() { QString e; Ownership::shared().release(Ownership::Owner::Legacy, e, generation); }
    } release{owned};
    NekoGui::dataStore->prepare_exit = false;
    NekoGui::dataStore->core_running = false;
    NekoGui_sys::CoreProcess core(QCoreApplication::applicationFilePath(), {QStringLiteral("--daemon-event-child")});
    // Prevent cleanup/destruction from scheduling another restart on failure.
    struct Stop {
        NekoGui_sys::CoreProcess &core;
        ~Stop() { NekoGui::dataStore->prepare_exit = true; core.Kill(); }
    } stop{core};
    core.start_profile_when_core_is_up = 77;
    core.Start();
    if (!core.waitForStarted(3000) || !until([&] { return events.size() >= 2; }, 5000)) return false;
    const auto started = events[0].split(',');
    const auto crashed = events[1].split(',');
    if (started.size() != 3 || crashed.size() != 3 || started[0] != "CoreStarted" || started[1] != "77" ||
        crashed[0] != "CoreCrashed" || crashed[1] != started[2] || crashed[2].toULongLong() != owned ||
        !core.acceptsGeneration(started[2].toULongLong()) || core.state() != QProcess::NotRunning) return false;
    const auto oldGeneration = started[2].toULongLong();
    // Restart manually while the production one-second retry is still queued.
    core.arguments = {QStringLiteral("--external-process-child")};
    core.Restart();
    if (!core.waitForStarted(3000) || core.acceptsGeneration(oldGeneration)) return false;
    const auto newPid = core.processId();
    core.Start(); // Duplicate start must not replace the active child.
    if (core.processId() != newPid) return false;
    QElapsedTimer settle;
    settle.start();
    until([&] { return settle.elapsed() >= 1300; }, 2000);
    if (core.processId() != newPid || core.state() != QProcess::Running || events.size() != 2) return false;
    NekoGui::dataStore->prepare_exit = true;
    core.Kill();
    if (core.state() != QProcess::NotRunning || events.size() != 2) return false;
    QTextStream(stdout) << "CORE_PROCESS_REAL_EVENTS_RESTART_STALE_TIMER_PASS\n";
    return true;
}
