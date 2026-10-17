#pragma once

#include "LegacyBackupFixture.hpp"
#include <QThread>
#include <QElapsedTimer>

namespace LegacyRestoreFixture {
using namespace LegacyBackupFixture;

inline Manifest originals() {
    auto files = seedFiles();
    files.remove("preservation.txt");
    files["profiles/205.json"] = "{synthetic-broken";
    return files;
}

inline bool restoredName(const QString &name) {
    return QRegularExpression("^legacy-restore-[0-9a-f]{32}$").match(name).hasMatch();
}

inline bool killedOracle(const QByteArray &output, bool wasRunning, bool finished, int exitCode) {
    auto normalized = output;
    normalized.replace("\r\n", "\n");
    return wasRunning && finished && exitCode != 0 &&
        normalized.split('\n').contains("LEGACY_MIGRATION_RESTORE_PAUSED") &&
        !normalized.contains("LEGACY_MIGRATION_FAIL");
}

// Only remove exact, independently checked fixture bytes. Unexpected entries
// prevent rmdir; aliases, non-fixture paths and unrecognized contents are retained.
inline bool cleanupRestored(const QString &root, const QString &target, const Manifest &files, const QByteArray &marker = {}) {
    const QFileInfo info(target);
    if (!restoredName(info.fileName()) || info.dir().canonicalPath() != root + "/restores" ||
        !plainPath(target, true) || !exactBytes(target, files)) return false;
    if (!marker.isEmpty()) {
        QByteArray actual;
        if (!readManifest(target + "/.restore-manifest.json", actual) || actual != marker ||
            !QFile::remove(target + "/.restore-manifest.json")) return false;
    } else if (QFileInfo::exists(target + "/.restore-manifest.json")) return false;
    for (auto it = files.begin(); it != files.end(); ++it) {
        if (!plainPath(target + '/' + it.key(), false) || !QFile::remove(target + '/' + it.key())) return false;
    }
    for (const auto &dir : Backup::Detail::Directories) if (!QDir().rmdir(target + '/' + dir)) return false;
    return QDir().rmdir(target);
}

inline int run(QCoreApplication &app) {
    const auto args = app.arguments();
    if (args.value(1) == "--legacy-migration-restore-child") {
        if (args.size() != 7 || !owned(args[2], args[3]) || !restoredName(args[4]) ||
            args[6] != "verify") return fail("restore-child-guard", 64);
        const auto target = args[2] + "/restores/" + args[4];
        if (!Backup::VerifyRestored(target, args[5].toLatin1()).ok() || !exactBytes(target, originals())) return fail("restore-child-verify");
        QTextStream(stdout) << "LEGACY_MIGRATION_RESTORE_REOPEN_PASS\n";
        return 0;
    }
    if (args.value(1) == "--legacy-migration-restore-interrupt-child") {
        if (args.size() != 5 || !owned(args[2], args[3]) ||
            !QRegularExpression("^legacy-backup-[0-9a-f]{32}$").match(args[4]).hasMatch()) return fail("restore-interrupt-guard", 64);
        const auto result = Backup::Detail::restore(args[2] + "/backups/" + args[4], args[2] + "/restores",
            [&](const QString &path, const QByteArray &bytes) {
                if (!Backup::Detail::writeNew(path, bytes)) return false;
                QTextStream out(stdout);
                out << "LEGACY_MIGRATION_RESTORE_PAUSED\n";
                out.flush();
                // Parent kills THIS owned child after first checked real write.
                QThread::sleep(60);
                return false;
            });
        Q_UNUSED(result)
        return fail("restore-interrupt-not-killed");
    }
    if (args != QStringList{args.first(), "--legacy-migration-restore"}) return fail("restore-arguments", 64);
    const QByteArray pauseMarker("LEGACY_MIGRATION_RESTORE_PAUSED\r\n");
    if (!killedOracle(pauseMarker, true, true, 1) ||
        killedOracle(pauseMarker + "LEGACY_MIGRATION_FAIL restore-interrupt-not-killed\r\n", true, true, 1) ||
        killedOracle(pauseMarker, false, true, 1) || killedOracle(pauseMarker, true, false, 1) ||
        killedOracle(pauseMarker, true, true, 0) || killedOracle("prefix LEGACY_MIGRATION_RESTORE_PAUSED\n", true, true, 1)) return fail("restore-kill-oracle-negative");
    if (!Backup::Detail::within("X:/owned/backup", "X:/") || !Backup::Detail::within("/owned/backup", "/") ||
        !Backup::Detail::within("X:/owned/backup", "X:/owned") || !Backup::Detail::within("X:/owned", "X:/owned") ||
        Backup::Detail::within("X:/owned2/backup", "X:/owned") || Backup::Detail::within("X:/restores", "X:/backup")) return fail("restore-root-paths");
    QTemporaryDir temporary(QDir::tempPath() + "/mdmbox-legacy-backup-XXXXXX");
    temporary.setAutoRemove(false);
    if (!temporary.isValid() || !plainPath(temporary.path(), true)) return fail("restore-root");
    const auto root = QFileInfo(temporary.path()).canonicalFilePath();
    const auto token = QUuid::createUuid().toString(QUuid::Id128);
    if (!writeNew(root + "/.owner", token.toUtf8()) || !owned(root, token)) return fail("restore-owner");
    for (const auto &dir : {"source", "backups", "restores"}) if (!QDir(root).mkdir(dir)) return fail("restore-dir");
    const auto source = root + "/source", parent = root + "/restores";
    for (const auto &dir : Backup::Detail::Directories) if (!QDir(source).mkdir(dir)) return fail("restore-source-dir");
    const auto files = originals();
    for (auto it = files.begin(); it != files.end(); ++it) if (!writeNew(source + '/' + it.key(), it.value())) return fail("restore-source-write");
    const auto backup = Backup::Create(source, root + "/backups");
    QByteArray marker;
    if (!backup.ok() || !readManifest(backup.directory + "/manifest.json", marker)) return fail("restore-backup");
    const auto digest = Backup::Detail::hash(marker);
    const auto preserved = [&] {
        QByteArray now;
        return exactBytes(source, files) && exactBytes(backup.directory + "/payload", files) &&
            readManifest(backup.directory + "/manifest.json", now) && now == marker && Backup::Verify(backup.directory).ok();
    };
    const auto first = Backup::Restore(backup.directory, parent);
    const auto second = Backup::Restore(backup.directory, parent);
    if (!first.ok() || !second.ok() || first.directory == second.directory || !preserved() ||
        !exactBytes(first.directory, files) || !exactBytes(second.directory, files) ||
        !Backup::VerifyRestored(first.directory, digest).ok()) return fail("restore-roundtrip");
    const auto child = QStringList{"--legacy-migration-restore-child", root, token,
        QFileInfo(first.directory).fileName(), QString::fromLatin1(digest), "verify"};
    if (!spawn(child, root, 0, "LEGACY_MIGRATION_RESTORE_REOPEN_PASS")) return fail("restore-reopen");
    auto wrong = child; wrong[2] = QString(32, '0');
    if (!spawn(wrong, root, 64, "LEGACY_MIGRATION_FAIL restore-child-guard")) return fail("restore-owner-refusal");
    wrong = child; wrong[4] = QString(64, '0');
    if (!spawn(wrong, root, 1, "LEGACY_MIGRATION_FAIL restore-child-verify")) return fail("restore-digest-refusal");
    const auto before = QDir(parent).entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    const auto victim = backup.directory + "/payload/profiles/205.json";
    if (!QFile::remove(victim) || !writeNew(victim, "synthetic-corruption") ||
        Backup::Restore(backup.directory, parent).status != Backup::Status::InvalidBackup ||
        QDir(parent).entryList(QDir::Dirs | QDir::NoDotAndDotDot) != before ||
        !QFile::remove(victim) || !writeNew(victim, files.value("profiles/205.json")) || !preserved()) return fail("restore-corrupt-refusal");
    if (!QFile::rename(backup.directory + "/manifest.json", backup.directory + "/incomplete.json") ||
        Backup::Restore(backup.directory, parent).status != Backup::Status::InvalidBackup ||
        QDir(parent).entryList(QDir::Dirs | QDir::NoDotAndDotDot) != before ||
        !QFile::rename(backup.directory + "/incomplete.json", backup.directory + "/manifest.json")) return fail("restore-incomplete-refusal");
    if (Backup::Restore(backup.directory, backup.directory).status != Backup::Status::UnsafePath ||
        Backup::Restore(backup.directory, root).status != Backup::Status::UnsafePath ||
        Backup::Restore(backup.directory, "relative").status != Backup::Status::UnsafePath) return fail("restore-path-refusal");

    Manifest partial;
    QString failed;
    const auto conflict = Backup::Detail::restore(backup.directory, parent, [&](const QString &path, const QByteArray &bytes) {
        const auto relative = QFileInfo(path).dir().dirName() + '/' + QFileInfo(path).fileName();
        if (failed.isEmpty()) { auto dir = QFileInfo(path).dir(); dir.cdUp(); failed = dir.canonicalPath(); }
        const auto value = partial.isEmpty() ? bytes : QByteArray("synthetic-existing-restore-destination");
        if (!Backup::Detail::writeNew(path, value)) return false;
        partial.insert(relative, value);
        return partial.size() == 1 || Backup::Detail::writeNew(path, bytes);
    });
    if (conflict.status != Backup::Status::WriteError || !conflict.directory.isEmpty() || partial.size() != 2 ||
        Backup::VerifyRestored(failed, digest).ok() || !preserved() ||
        !cleanupRestored(root, failed, partial)) return fail("restore-partial-conflict");

    // Exact verifier must reject a previously ready tree after each corruption.
    const auto restoredVictim = second.directory + "/profiles/205.json";
    if (!QFile::remove(restoredVictim) || !writeNew(restoredVictim, "synthetic-restored-corruption") ||
        Backup::VerifyRestored(second.directory, digest).ok() || !QFile::remove(restoredVictim) ||
        !writeNew(restoredVictim, files.value("profiles/205.json"))) return fail("restore-corrupt-output");
    if (!writeNew(second.directory + "/profiles/extra.json", "extra") || Backup::VerifyRestored(second.directory, digest).ok() ||
        !QFile::remove(second.directory + "/profiles/extra.json")) return fail("restore-extra-output");
    if (!QFile::remove(second.directory + "/.restore-manifest.json") || !writeNew(second.directory + "/.restore-manifest.json", "{}") ||
        Backup::VerifyRestored(second.directory, digest).ok() || !QFile::remove(second.directory + "/.restore-manifest.json") ||
        !writeNew(second.directory + "/.restore-manifest.json", marker) || !Backup::VerifyRestored(second.directory, digest).ok()) return fail("restore-marker-output");

    QString changedRoot;
    bool changed = false;
    const auto sourceChanged = Backup::Detail::restore(backup.directory, parent, [&](const QString &path, const QByteArray &bytes) {
        if (!Backup::Detail::writeNew(path, bytes)) return false;
        if (changedRoot.isEmpty()) { auto dir = QFileInfo(path).dir(); dir.cdUp(); changedRoot = dir.canonicalPath(); }
        if (!changed) {
            changed = QFile::remove(victim) && writeNew(victim, "synthetic-backup-changed-during-restore");
            if (!changed) return false;
        }
        return true;
    });
    if (sourceChanged.status != Backup::Status::SourceChanged || !sourceChanged.directory.isEmpty() || !changed ||
        Backup::VerifyRestored(changedRoot, digest).ok() || !exactBytes(changedRoot, files) ||
        !QFile::remove(victim) || !writeNew(victim, files.value("profiles/205.json")) || !preserved() ||
        !cleanupRestored(root, changedRoot, files)) return fail("restore-source-changed");

    QProcess interrupted;
    interrupted.setWorkingDirectory(root);
    interrupted.start(QCoreApplication::applicationFilePath(), {"--legacy-migration-restore-interrupt-child", root, token,
        QFileInfo(backup.directory).fileName()});
    if (!interrupted.waitForStarted(10000)) return fail("restore-interrupt-start");
    QByteArray output;
    QElapsedTimer deadline; deadline.start();
    while (!output.contains("LEGACY_MIGRATION_RESTORE_PAUSED\n") && deadline.elapsed() < 15000 && interrupted.state() != QProcess::NotRunning) {
        interrupted.waitForReadyRead(500);
        output += interrupted.readAllStandardOutput();
        output.replace("\r\n", "\n");
    }
    const bool running = interrupted.state() == QProcess::Running;
    interrupted.kill();
    // Windows TerminateProcess can be reported as NormalExit by Qt. Require the
    // paused child was live, kill completed, nonzero exit and no completion path.
    const auto finished = interrupted.waitForFinished(5000);
    output += interrupted.readAllStandardOutput();
    output += interrupted.readAllStandardError();
    if (!killedOracle(output, running, finished, interrupted.exitCode())) return fail("restore-interrupt-kill");
    auto remaining = QDir(parent).entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const auto &name : before) remaining.removeAll(name);
    if (remaining.size() != 1 || !restoredName(remaining.first())) return fail("restore-interrupt-layout");
    const auto interruptedRoot = parent + '/' + remaining.first();
    Manifest one; one.insert(files.firstKey(), files.first());
    if (Backup::VerifyRestored(interruptedRoot, digest).ok() || !preserved() || !exactBytes(interruptedRoot, one)) return fail("restore-interrupt-preservation");
    const auto retry = Backup::Restore(backup.directory, parent);
    if (!retry.ok() || !exactBytes(retry.directory, files) || !preserved() ||
        !Backup::VerifyRestored(first.directory, digest).ok() || !exactBytes(first.directory, files) ||
        !exactBytes(interruptedRoot, one) || Backup::VerifyRestored(interruptedRoot, digest).ok()) return fail("restore-retry");
    if (!cleanupRestored(root, interruptedRoot, one)) return fail("restore-interrupt-cleanup");
    for (const auto &target : {first.directory, second.directory, retry.directory}) {
        if (!cleanupRestored(root, target, files, marker)) return fail("restore-cleanup");
    }
    if (!cleanupBackup(root, QFileInfo(backup.directory).fileName())) return fail("restore-backup-cleanup");
    for (auto it = files.begin(); it != files.end(); ++it) if (!QFile::remove(source + '/' + it.key())) return fail("restore-source-cleanup");
    for (const auto &dir : Backup::Detail::Directories) if (!QDir().rmdir(source + '/' + dir)) return fail("restore-source-dir-cleanup");
    for (const auto &dir : {source, parent, root + "/backups"}) if (!QDir().rmdir(dir)) return fail("restore-parent-cleanup");
    if (!QFile::remove(root + "/.owner") || !QDir().rmdir(root) || QFileInfo::exists(root)) return fail("restore-root-cleanup");
    QTextStream(stdout) << "LEGACY_MIGRATION_RESTORE_PASS scope=detached-directories interruption=kill-v1 acceptance=NOT_ACCEPTED\n";
    return 0;
}
} // namespace LegacyRestoreFixture
