#include "ExternalProcess.hpp"
#include "main/NekoGui.hpp"
#include "sub/CoreOwnership.hpp"

#include <QTimer>
#include <QDir>
#include <QApplication>
#include <QElapsedTimer>

namespace NekoGui_sys {

    ExternalProcess::ExternalProcess() : QProcess() {
        // qDebug() << "[Debug] ExternalProcess()" << this << running_ext;
        this->env = QProcessEnvironment::systemEnvironment().toStringList();
    }

    ExternalProcess::~ExternalProcess() {
        // qDebug() << "[Debug] ~ExternalProcess()" << this << running_ext;
    }

    void ExternalProcess::Start() {
        if (started) return;
        started = true;

        if (managed) {
            connect(this, &QProcess::readyReadStandardOutput, this, [&]() {
                auto log = readAllStandardOutput();
                if (logCounter.fetchAndAddRelaxed(log.count("\n")) > NekoGui::dataStore->max_log_line) return;
                MW_show_log_ext_vt100(log);
            });
            connect(this, &QProcess::readyReadStandardError, this, [&]() {
                MW_show_log_ext_vt100(readAllStandardError().trimmed());
            });
            connect(this, &QProcess::errorOccurred, this, [&](QProcess::ProcessError error) {
                if (!killed) {
                    crashed = true;
                    MW_show_log_ext(tag, "errorOccurred:" + errorString());
                    MW_dialog_message("ExternalProcess", "Crashed");
                }
            });
            connect(this, &QProcess::stateChanged, this, [&](QProcess::ProcessState state) {
                if (state == QProcess::NotRunning) {
                    if (killed) { // 用户命令退出
                        MW_show_log_ext(tag, "External core stopped");
                    } else if (!crashed) { // 异常退出
                        crashed = true;
                        MW_show_log_ext(tag, "[Error] Program exited accidentally: " + errorString());
                        Kill();
                        MW_dialog_message("ExternalProcess", "Crashed");
                    }
                }
            });
            MW_show_log_ext(tag, "External core starting: " + env.join(" ") + " " + program + " " + arguments.join(" "));
        }

        QProcess::setEnvironment(env);
        QProcess::start(program, arguments);
    }

    void ExternalProcess::Kill() {
        // This flag suppresses intentional-stop crash notifications; it is
        // not proof that an earlier kill/wait completed. Retry live children
        // even after a timeout or an error notification set crashed.
        killed = true;

        if (state() != QProcess::NotRunning) {
            QProcess::kill();
            QProcess::waitForFinished(500);
        }
    }

    //

    QElapsedTimer coreRestartTimer;

    CoreProcess::CoreProcess(const QString &core_path, const QStringList &args) : ExternalProcess() {
        ExternalProcess::managed = false;
        ExternalProcess::program = core_path;
        ExternalProcess::arguments = args;

        connect(this, &QProcess::readyReadStandardOutput, this, [&]() {
            auto log = readAllStandardOutput();
            if (!NekoGui::dataStore->core_running) {
                if (log.contains("grpc server listening")) {
                    // The core really started
                    NekoGui::dataStore->core_running = true;
                    if (start_profile_when_core_is_up >= 0) {
                        MW_dialog_message("ExternalProcess", QStringLiteral("CoreStarted,%1,%2")
                            .arg(start_profile_when_core_is_up).arg(generationCounter.current()));
                        start_profile_when_core_is_up = -1;
                    }
                } else if (log.contains("failed to serve")) {
                    // The core failed to start
                    QProcess::kill();
                }
            }
            if (logCounter.fetchAndAddRelaxed(log.count("\n")) > NekoGui::dataStore->max_log_line) return;
            MW_show_log(log);
        });
        connect(this, &QProcess::readyReadStandardError, this, [&]() {
            auto log = readAllStandardError().trimmed();
            if (show_stderr) {
                MW_show_log(log);
                return;
            }
            if (log.contains("token is set")) {
                show_stderr = true;
            }
        });
        connect(this, &QProcess::errorOccurred, this, [&](QProcess::ProcessError error) {
            if (error == QProcess::ProcessError::FailedToStart) {
                failed_to_start = true;
                MW_show_log("start core error occurred: " + errorString() + "\n");
            }
        });
        connect(this, &QProcess::stateChanged, this, [&](QProcess::ProcessState state) {
            if (state == QProcess::NotRunning) {
                NekoGui::dataStore->core_running = false;
            }

            if (!NekoGui::dataStore->prepare_exit && state == QProcess::NotRunning) {
                if (failed_to_start) return; // no retry
                if (restarting) return;

                const auto ownershipGeneration = NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Legacy);
                MW_dialog_message("ExternalProcess", QStringLiteral("CoreCrashed,%1,%2")
                    .arg(generationCounter.current()).arg(ownershipGeneration));

                // Retry rate limit
                if (coreRestartTimer.isValid()) {
                    if (coreRestartTimer.restart() < 10 * 1000) {
                        coreRestartTimer = QElapsedTimer();
                        MW_show_log("[Error] " + QObject::tr("Core exits too frequently, stop automatic restart this profile."));
                        return;
                    }
                } else {
                    coreRestartTimer.start();
                }

                // Restart
                start_profile_when_core_is_up = NekoGui::dataStore->started_id;
                MW_show_log("[Error] " + QObject::tr("Core exited, restarting."));
                const auto failedGeneration = generationCounter.current();
                setTimeout([=] {
                    if (generationCounter.accepts(failedGeneration) && this->state() == QProcess::NotRunning) Restart();
                }, this, 1000);
            }
        });
    }

    void CoreProcess::Start() {
        if (started || state() != QProcess::NotRunning) return;
        if (!generationCounter.advance()) {
            MW_show_log(QStringLiteral("Core process generation exhausted; restart the application"));
            return;
        }
        show_stderr = false;
        // cwd: same as GUI, at ./config
        ExternalProcess::Start();
        write((NekoGui::dataStore->core_token + "\n").toUtf8());
    }

    void CoreProcess::Restart() {
        restarting = true;
        QProcess::kill();
        QProcess::waitForFinished(500);
        if (state() != QProcess::NotRunning) {
            restarting = false;
            MW_show_log(QStringLiteral("Core restart refused: previous process exit is unconfirmed"));
            return;
        }
        ExternalProcess::started = false;
        Start();
        restarting = false;
    }

} // namespace NekoGui_sys
