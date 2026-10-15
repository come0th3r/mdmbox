#pragma once

#include "sys/ExternalProcess.hpp"
#include "sys/TrackedProcessCleanup.hpp"
#include "sub/LegacyCoreLifecycle.hpp"
#include <QCoreApplication>
#include <QTextStream>

// Flags reproduce a previous incomplete stop/error while the real child is
// still running. No fake kill or wait implementation is used here.
class ExternalProcessFixture : public NekoGui_sys::ExternalProcess {
public:
    void previousOutcome(bool previousKill, bool previousCrash) {
        killed = previousKill;
        crashed = previousCrash;
    }
};

inline bool runExternalProcessFixture() {
    using Ownership = NekoGui_sub::CoreOwnership;
    for (const bool previousKill : {false, true}) {
        for (const bool previousCrash : {false, true}) {
            auto child = std::make_shared<ExternalProcessFixture>();
            child->managed = false; // Avoid production UI/log callbacks in fixture.
            child->program = QCoreApplication::applicationFilePath();
            child->arguments = {QStringLiteral("--external-process-child")};
            child->setStandardOutputFile(QProcess::nullDevice());
            child->setStandardErrorFile(QProcess::nullDevice());
            child->Start();
            if (!child->waitForStarted(3000) || child->processId() == 0) return false;
            child->previousOutcome(previousKill, previousCrash);
            std::list<std::shared_ptr<ExternalProcessFixture>> tracked{child};
            Ownership ownership;
            QString error;
            if (!ownership.acquire(Ownership::Owner::Legacy, error)) return false;
            const bool cleaned = NekoGui_sys::cleanupTrackedProcesses(tracked,
                [](ExternalProcessFixture &process) { process.Kill(); });
            if (!cleaned || child->state() != QProcess::NotRunning || child->processId() != 0 ||
                !NekoGui_sub::LegacyCoreLifecycle::finishStop(ownership, true, cleaned, error) ||
                !ownership.acquire(Ownership::Owner::Managed, error)) return false;
            child->Kill(); // Repeated stop of an exited child is harmless.
            if (child->state() != QProcess::NotRunning) return false;
        }
    }
    QTextStream(stdout) << "EXTERNAL_PROCESS_REAL_KILL_RETRY_PASS cases=4\n";
    return true;
}
