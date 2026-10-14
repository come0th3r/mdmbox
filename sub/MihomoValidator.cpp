#include "MihomoValidator.hpp"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>

namespace NekoGui_sub {
    bool MihomoValidator::verifyExecutable(const QString &executable, QString &error) {
        error.clear();
        QFile binary(executable);
        if (!QFileInfo(executable).isAbsolute() || !binary.open(QIODevice::ReadOnly)) {
            error = QStringLiteral("Pinned mihomo executable unavailable");
            return false;
        }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (!hash.addData(&binary) || hash.result().toHex() !=
            "0b54ea7b10e26f6ca628b49e77c13ad9b2587b23393a5b715769cbaeed012af6") {
            error = QStringLiteral("Mihomo executable checksum mismatch");
            return false;
        }
        binary.close();
        return true;
    }

    bool MihomoValidator::validate(const QString &executable, const ManagedProfile &profile, QString &error) {
        if (!verifyExecutable(executable, error)) return false;
        if (profile.source.isEmpty() || profile.source.size() > 4 * 1024 * 1024) {
            error = QStringLiteral("Invalid managed profile size");
            return false;
        }
        QTemporaryDir home;
        if (!home.isValid()) {
            error = QStringLiteral("Isolated validation directory unavailable");
            return false;
        }
        auto environment = QProcessEnvironment::systemEnvironment();
        for (const auto &key : environment.keys()) {
            if (key.startsWith("CLASH_", Qt::CaseInsensitive)) environment.remove(key);
        }
        QProcess process;
        process.setProcessEnvironment(environment);
        process.setWorkingDirectory(home.path());
        // -f - feeds stdin and skips config.Init; -t exits before runtime listeners/TUN.
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        process.start(executable, {"-t", "-d", home.path(), "-f", "-"});
        if (!process.waitForStarted(5000)) {
            process.kill();
            process.waitForFinished(1000);
            error = QStringLiteral("Mihomo validation process failed to start");
            return false;
        }
        if (process.write(profile.source) != profile.source.size()) {
            process.kill();
            process.waitForFinished(1000);
            error = QStringLiteral("Mihomo validation input failed");
            return false;
        }
        process.closeWriteChannel();
        if (!process.waitForFinished(15000) && process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished(1000);
            error = QStringLiteral("Mihomo validation timed out");
            return false;
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            error = QStringLiteral("Pinned mihomo rejected the configuration");
            return false;
        }
        return true;
    }
}
