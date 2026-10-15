#include "ManagedCoreProcess.hpp"
#include "ManagedRuntimePolicy.hpp"
#include "MihomoValidator.hpp"
#include <QProcessEnvironment>
#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace NekoGui_sub {
    ManagedCoreProcess::~ManagedCoreProcess() { forceCleanup(); }

    bool ManagedCoreProcess::forceCleanup() {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            if (!process.waitForFinished(3000)) {
                if (home) home->setAutoRemove(false);
                return false;
            }
        }
        home.reset(); // Never remove home while the owned child is known to be running.
        return true;
    }

    ManagedCoreProcess::State ManagedCoreProcess::state() const {
        if (current == State::Running && process.state() == QProcess::NotRunning) return State::Failed;
        return current;
    }

    qint64 ManagedCoreProcess::processId() const { return process.processId(); }

    bool ManagedCoreProcess::start(const QString &executable, const ManagedProfile &panel, int mixedPort,
                                   int apiPort, const QByteArray &apiToken, QString &error) {
        error.clear();
        if (process.state() != QProcess::NotRunning || current == State::Starting || current == State::Stopping) {
            error = QStringLiteral("Managed core already owns an active process");
            return false;
        }
        current = State::Starting;
        ManagedProfile projected;
        if (!ManagedRuntimePolicy::projectLoopback(panel, mixedPort, apiPort, apiToken, projected, error) ||
            !MihomoValidator::validate(executable, projected, error)) {
            current = State::Failed;
            return false;
        }
        home = std::make_unique<QTemporaryDir>();
        if (!home->isValid()) {
            home.reset();
            current = State::Failed;
            error = QStringLiteral("Managed runtime directory unavailable");
            return false;
        }
        auto environment = QProcessEnvironment::systemEnvironment();
        for (const auto &key : environment.keys())
            if (key.startsWith("CLASH_", Qt::CaseInsensitive)) environment.remove(key);
        process.setProcessEnvironment(environment);
        process.setWorkingDirectory(home->path());
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
#ifdef Q_OS_WIN
        process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
            args->flags &= ~CREATE_NO_WINDOW;
            args->flags |= CREATE_NEW_CONSOLE;
            args->startupInfo->dwFlags |= STARTF_USESHOWWINDOW;
            args->startupInfo->wShowWindow = SW_HIDE;
        });
#endif
        process.start(executable, {"-d", home->path(), "-f", "-"});
        if (!process.waitForStarted(5000) || process.write(projected.source) != projected.source.size()) {
            forceCleanup();
            current = State::Failed;
            error = QStringLiteral("Managed core start or input failed");
            return false;
        }
        process.closeWriteChannel();
        current = State::Running; // Readiness belongs to authenticated API checks, not process start.
        return true;
    }

    bool ManagedCoreProcess::stop(const StopSignal &signal, QString &error) {
        error.clear();
        if (process.state() == QProcess::NotRunning) {
            const bool unexpectedlyExited = current == State::Running;
            home.reset();
            current = unexpectedlyExited ? State::Failed : State::Stopped;
            if (unexpectedlyExited) error = QStringLiteral("Managed core exited before requested stop");
            return !unexpectedlyExited;
        }
        current = State::Stopping;
        bool sent = false;
        try { if (signal) sent = signal(process.processId()); } catch (...) { sent = false; }
        const bool finished = process.state() == QProcess::NotRunning || process.waitForFinished(5000);
        const bool graceful = sent && finished && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const bool cleaned = forceCleanup();
        current = graceful && cleaned ? State::Stopped : State::Failed;
        if (!graceful || !cleaned) {
            error = QStringLiteral("Managed core required forced cleanup or failed to stop");
            return false;
        }
        return true;
    }
}
