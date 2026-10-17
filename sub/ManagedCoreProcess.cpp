#include "ManagedCoreProcess.hpp"
#include "ManagedRuntimePolicy.hpp"
#include "MihomoValidator.hpp"
#include "ManagedControllerProbe.hpp"
#include "CoreOwnership.hpp"
#include <QProcessEnvironment>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTimer>
#include <algorithm>
#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace NekoGui_sub {
    ManagedCoreProcess::~ManagedCoreProcess() { forceCleanup(); }

    bool ManagedCoreProcess::forceCleanup() {
        if (process.state() != QProcess::NotRunning) {
            if (forceKillSignal) {
                try { forceKillSignal(process.processId()); } catch (...) {}
            } else {
                process.kill();
            }
            if (!process.waitForFinished(3000)) {
                QString ignored;
                if (ownsRuntime) CoreOwnership::shared().markUncertain(CoreOwnership::Owner::Managed, ignored, ownershipGeneration);
                if (home) home->setAutoRemove(false);
                return false;
            }
        }
        home.reset(); // Never remove home while the owned child is known to be running.
        controllerToken.clear();
        controllerPort = 0;
        if (ownsRuntime) {
            QString ignored;
            if (!CoreOwnership::shared().release(CoreOwnership::Owner::Managed, ignored, ownershipGeneration)) return false;
            ownsRuntime = false;
            ownershipGeneration = 0;
        }
        return true;
    }

    ManagedCoreProcess::State ManagedCoreProcess::state() const {
        if ((current == State::Running || current == State::Ready) && process.state() == QProcess::NotRunning) return State::Failed;
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
        // Reap any previous failed generation before acquiring a new one.
        if (!forceCleanup()) {
            error = QStringLiteral("Previous managed core cleanup is not confirmed");
            return false;
        }
        if (!CoreOwnership::shared().acquire(CoreOwnership::Owner::Managed, error, &ownershipGeneration)) return false;
        ownsRuntime = true;
        current = State::Starting;
        ManagedProfile projected;
        if (!ManagedRuntimePolicy::projectLoopback(panel, mixedPort, apiPort, apiToken, projected, error) ||
            !MihomoValidator::validate(executable, projected, error)) {
            forceCleanup();
            current = State::Failed;
            return false;
        }
        home = std::make_unique<QTemporaryDir>();
        if (!home->isValid()) {
            forceCleanup();
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
        controllerPort = apiPort;
        controllerToken = apiToken;
        current = State::Running; // Readiness belongs to authenticated API checks, not process start.
        return true;
    }

    bool ManagedCoreProcess::waitReady(int timeoutMs, QString &error) {
        error.clear();
        if (timeoutMs < 1 || timeoutMs > 30000) {
            error = QStringLiteral("Managed readiness timeout must be 1..30000 ms");
            return false;
        }
        if ((current != State::Running && current != State::Ready) || process.state() == QProcess::NotRunning) {
            error = QStringLiteral("Managed readiness requires a live owned process");
            return false;
        }
        current = State::Running;
        QElapsedTimer deadline;
        deadline.start();
        bool refused = false;
        while (deadline.elapsed() < timeoutMs && process.state() != QProcess::NotRunning && !refused) {
            const auto result = ManagedControllerProbe::version(controllerPort, controllerToken,
                (std::max)(1, (std::min)(500, timeoutMs - static_cast<int>(deadline.elapsed()))));
            refused = result == ManagedControllerProbe::Result::Rejected;
            if (result == ManagedControllerProbe::Result::Accepted && process.state() != QProcess::NotRunning) {
                current = State::Ready;
                return true;
            }
            const auto remaining = timeoutMs - static_cast<int>(deadline.elapsed());
            if (!refused && remaining > 0) {
                QEventLoop pause;
                QTimer::singleShot((std::min)(50, remaining), &pause, &QEventLoop::quit);
                pause.exec();
            }
        }
        forceCleanup();
        current = State::Failed;
        error = QStringLiteral("Managed controller readiness failed");
        return false;
    }

    bool ManagedCoreProcess::stop(QString &error) {
        return stop([this](qint64 pid) {
#ifdef Q_OS_WIN
            QProcess helper;
            helper.setStandardOutputFile(QProcess::nullDevice());
            helper.setStandardErrorFile(QProcess::nullDevice());
            helper.start(QCoreApplication::applicationDirPath() + QStringLiteral("/mdmbox_console_signal.exe"),
                         {QString::number(pid)});
            if (!helper.waitForStarted(2000)) return false;
            if (!helper.waitForFinished(3000)) {
                helper.kill();
                helper.waitForFinished(1000);
                return false;
            }
            return helper.exitStatus() == QProcess::NormalExit && helper.exitCode() == 0;
#else
            Q_UNUSED(pid)
            process.terminate();
            return true;
#endif
        }, error);
    }

    bool ManagedCoreProcess::stop(const StopSignal &signal, QString &error) {
        error.clear();
        if (process.state() == QProcess::NotRunning) {
            const bool unexpectedlyExited = current == State::Running || current == State::Ready;
            forceCleanup();
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
