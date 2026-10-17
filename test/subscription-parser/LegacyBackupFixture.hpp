#pragma once

#include "LegacyMigrationFixture.hpp"
#include "db/LegacyBackup.hpp"
#ifndef Q_OS_WIN
#include <unistd.h>
#endif

namespace LegacyBackupFixture {
using namespace LegacyMigrationFixture;
namespace Backup = NekoGui::LegacyBackup;

// Independent byte oracle: enumerate fixture expectations, not production scan.
inline bool exactBytes(const QString &root, const Manifest &expected) {
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        QFile file(root + '/' + it.key());
        if (!file.open(QIODevice::ReadOnly) || file.readAll() != it.value() || file.error() != QFileDevice::NoError) return false;
    }
    return true;
}

inline bool readManifest(const QString &path, QByteArray &bytes) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > Backup::Detail::MaxManifestBytes) return false;
    bytes = file.readAll();
    return file.error() == QFileDevice::NoError;
}

#ifdef Q_OS_WIN
class NormalFilePrivileges {
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES previous[2]{};
    int changed = 0;
public:
    bool disable() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
        for (const auto name : {SE_BACKUP_NAME, SE_RESTORE_NAME}) {
            TOKEN_PRIVILEGES request{};
            request.PrivilegeCount = 1;
            if (!LookupPrivilegeValueW(nullptr, name, &request.Privileges[0].Luid)) return false;
            DWORD length = sizeof(TOKEN_PRIVILEGES);
            if (!AdjustTokenPrivileges(token, FALSE, &request, sizeof(TOKEN_PRIVILEGES), &previous[changed], &length)) return false;
            ++changed;
        }
        return true;
    }
    ~NormalFilePrivileges() {
        if (!token) return;
        for (int i = changed - 1; i >= 0; --i) AdjustTokenPrivileges(token, FALSE, &previous[i], 0, nullptr, nullptr);
        CloseHandle(token);
    }
};

inline bool icacls(const QStringList &arguments) {
    QProcess process;
    process.start(qEnvironmentVariable("SystemRoot") + "/System32/icacls.exe", arguments);
    if (!process.waitForFinished(10000)) { process.kill(); process.waitForFinished(5000); return false; }
    return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
}

// Only owned fixture directories; no inherited ACL reset or real appdata edits.
inline bool listingDenied(const QString &source, const QString &parent, const QString &backup) {
    QProcess identity;
    identity.start(qEnvironmentVariable("SystemRoot") + "/System32/whoami.exe", {"/user", "/fo", "csv", "/nh"});
    if (!identity.waitForFinished(10000) || identity.exitCode() != 0) { fail("backup-acl-identity"); return false; }
    const auto match = QRegularExpression("S-1-[0-9-]+").match(QString::fromLocal8Bit(identity.readAllStandardOutput()));
    if (!match.hasMatch()) { fail("backup-acl-sid"); return false; }
    const auto sid = "*" + match.captured();
    const auto input = source + "/profiles";
    if (!icacls({QDir::toNativeSeparators(input), "/deny", sid + ":(RD)"})) { fail("backup-acl-deny-input"); return false; }
    const auto result = Backup::Create(source, parent);
    const auto restored = icacls({QDir::toNativeSeparators(input), "/remove:d", sid});
    if (!restored || result.status != Backup::Status::SourceError) {
        QTextStream(stdout) << "LEGACY_MIGRATION_FAIL backup-acl-input-status status=" << static_cast<int>(result.status) << " reset=" << restored << '\n';
        return false;
    }
    const auto output = backup + "/payload/profiles";
    if (!icacls({QDir::toNativeSeparators(output), "/deny", sid + ":(RD)"})) { fail("backup-acl-deny-output"); return false; }
    const auto verified = Backup::Verify(backup);
    const auto reset = icacls({QDir::toNativeSeparators(output), "/remove:d", sid});
    if (!reset || verified.ok() || !Backup::Verify(backup).ok()) { fail("backup-acl-output-status"); return false; }
    return true;
}

#endif

inline bool partialWriteConflict(const QString &source, const QString &parent) {
    QStringList written;
    const QByteArray sentinel("synthetic-existing-destination");
    const auto result = Backup::Detail::create(source, parent, [&](const QString &path, const QByteArray &bytes) {
        if (written.size() == 1) {
            if (!writeNew(path, sentinel)) return false;
            written.append(path);
            return Backup::Detail::writeNew(path, bytes); // Real NewOnly refusal, must not clobber sentinel.
        }
        if (!Backup::Detail::writeNew(path, bytes)) return false;
        written.append(path);
        return true;
    });
    if (result.status != Backup::Status::WriteError || !result.directory.isEmpty() || written.size() != 2) return false;
    QByteArray actual;
    if (!readFile(written.last(), actual) || actual != sentinel) return false;
    auto directory = QFileInfo(written.first()).dir();
    if (!directory.cdUp()) return false;
    const auto payload = directory.canonicalPath();
    if (!directory.cdUp()) return false;
    const auto failed = directory.canonicalPath();
    if (directory.dirName().isEmpty() || !QRegularExpression("^legacy-backup-[0-9a-f]{32}$").match(directory.dirName()).hasMatch() ||
        QFileInfo(failed).dir().canonicalPath() != QFileInfo(parent).canonicalFilePath()) return false;
    if (Backup::Verify(failed).ok() || QFileInfo::exists(failed + "/manifest.json")) return false;
    for (const auto &file : written) if (!QFile::remove(file)) return false;
    for (const auto &dir : Backup::Detail::Directories) if (!QDir().rmdir(payload + '/' + dir)) return false;
    return QDir().rmdir(payload) && QDir().rmdir(failed);
}

// Exact, bounded tree owner. No input path supplied by the user is accepted.
inline bool owned(const QString &root, const QString &token) {
    const QFileInfo info(root);
    QByteArray marker;
    return QRegularExpression("^[0-9a-f]{32}$").match(token).hasMatch() && plainPath(root, true) &&
        info.dir().canonicalPath() == QFileInfo(QDir::tempPath()).canonicalFilePath() &&
        info.fileName().startsWith("mdmbox-legacy-backup-") &&
        readFile(root + "/.owner", marker) && marker == token.toUtf8();
}

inline bool cleanupBackup(const QString &root, const QString &name) {
    if (!QRegularExpression("^legacy-backup-[0-9a-f]{32}$").match(name).hasMatch()) return false;
    const auto target = root + "/backups/" + name;
    if (!plainPath(target, true)) return false;
    const auto files = seedFiles();
    for (auto it = files.begin(); it != files.end(); ++it) {
        if (it.key() == "preservation.txt") continue;
        if (!QFile::remove(target + "/payload/" + it.key())) return false;
    }
    for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
        if (!QDir().rmdir(target + "/payload/" + dir)) return false;
    }
    if (!QDir().rmdir(target + "/payload") || !QFile::remove(target + "/manifest.json")) return false;
    return QDir().rmdir(target);
}

inline int run(QCoreApplication &app) {
    const auto args = app.arguments();
    if (args.value(1) == "--legacy-migration-backup-verify-child") {
        if (args.size() != 6 || !owned(args[2], args[3]) ||
            !QRegularExpression("^legacy-backup-[0-9a-f]{32}$").match(args[4]).hasMatch()) return fail("backup-child-guard", 64);
        const auto target = args[2] + "/backups/" + args[4];
        QByteArray marker;
        if (!readManifest(target + "/manifest.json", marker) ||
            Backup::Detail::hash(marker) != args[5].toLatin1() || !Backup::Verify(target).ok()) return fail("backup-child-verify");
        QTextStream(stdout) << "LEGACY_MIGRATION_BACKUP_REOPEN_PASS\n";
        return 0;
    }
    if (args != QStringList{args.first(), "--legacy-migration-backup"}) return fail("backup-arguments", 64);
    QTemporaryDir temporary(QDir::tempPath() + "/mdmbox-legacy-backup-XXXXXX");
    temporary.setAutoRemove(false);
    if (!temporary.isValid() || !plainPath(temporary.path(), true)) return fail("backup-root");
    const auto root = QFileInfo(temporary.path()).canonicalFilePath();
    const auto token = QUuid::createUuid().toString(QUuid::Id128);
    if (!writeNew(root + "/.owner", token.toUtf8()) || !owned(root, token) ||
        !QDir(root).mkdir("source") || !QDir(root).mkdir("backups")) return fail("backup-owner");
    const auto source = root + "/source", parent = root + "/backups";
    for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
        if (!QDir(source).mkdir(dir)) return fail("backup-dir");
    }
    auto original = seedFiles();
    original.remove("preservation.txt");
    original["profiles/205.json"] = "{synthetic-broken"; // Raw corruption must be copied, not parsed away.
    for (auto it = original.begin(); it != original.end(); ++it) {
        if (!writeNew(source + '/' + it.key(), it.value())) return fail("backup-source");
    }
    const auto sourceExact = [&] {
        Backup::Detail::Files actual;
        return Backup::Detail::scan(source, actual) && actual == original && exactBytes(source, original);
    };
    const auto first = Backup::Create(source, parent);
    if (!first.ok() || !sourceExact() || !Backup::Verify(first.directory).ok()) return fail("backup-create");
    Backup::Detail::Files copied;
    if (!Backup::Detail::scan(first.directory + "/payload", copied) || copied != original ||
        !exactBytes(first.directory + "/payload", original)) return fail("backup-bytes");
    QByteArray manifest;
    if (!readFile(first.directory + "/manifest.json", manifest)) return fail("backup-manifest");
    const auto name = QFileInfo(first.directory).fileName();
    const auto childArgs = QStringList{"--legacy-migration-backup-verify-child", root, token, name,
        QString::fromLatin1(Backup::Detail::hash(manifest))};
    if (!spawn(childArgs, root, 0, "LEGACY_MIGRATION_BACKUP_REOPEN_PASS")) return fail("backup-reopen");
    auto wrong = childArgs; wrong[2] = QString(32, '0');
    if (!spawn(wrong, root, 64, "LEGACY_MIGRATION_FAIL backup-child-guard")) return fail("backup-child-negative");

    // A second backup must not replace or invalidate the first one.
    const auto second = Backup::Create(source, parent);
    QByteArray firstAfter;
    if (!second.ok() || second.directory == first.directory || !Backup::Verify(first.directory).ok() ||
        !readManifest(first.directory + "/manifest.json", firstAfter) || firstAfter != manifest ||
        !exactBytes(first.directory + "/payload", original) || !sourceExact()) return fail("backup-repeat");
    // Incomplete layout and corruption must fail closed, without touching source.
    if (!QFile::rename(second.directory + "/manifest.json", second.directory + "/incomplete.json") ||
        Backup::Verify(second.directory).ok() || !sourceExact() ||
        !QFile::rename(second.directory + "/incomplete.json", second.directory + "/manifest.json")) return fail("backup-incomplete");
    const auto victim = second.directory + "/payload/profiles/205.json";
    if (!QFile::remove(victim) || !writeNew(victim, "synthetic-corrupted-backup") ||
        Backup::Verify(second.directory).ok() || !sourceExact() ||
        !QFile::remove(victim) || !writeNew(victim, original.value("profiles/205.json"))) return fail("backup-corruption");
    if (!writeNew(second.directory + "/payload/profiles/extra.json", "synthetic-extra") ||
        Backup::Verify(second.directory).ok() || !QFile::remove(second.directory + "/payload/profiles/extra.json")) return fail("backup-extra");
    if (!QFile::remove(second.directory + "/manifest.json") || !writeNew(second.directory + "/manifest.json", "{}") ||
        Backup::Verify(second.directory).ok() || !QFile::remove(second.directory + "/manifest.json") ||
        !writeNew(second.directory + "/manifest.json", manifest) || !Backup::Verify(second.directory).ok()) return fail("backup-bad-manifest");
    if (Backup::Create(source, source).ok() || Backup::Create("relative", parent).ok() ||
        Backup::Create(source, root + "/missing").ok() || !sourceExact()) return fail("backup-path-refusal");
    if (!QDir(source + "/profiles").mkdir("unexpected") || Backup::Create(source, parent).ok() ||
        !QDir().rmdir(source + "/profiles/unexpected")) return fail("backup-nested-source");
#ifdef Q_OS_WIN
    NormalFilePrivileges normalPrivileges;
    if (!normalPrivileges.disable()) return fail("backup-normal-privileges");
    if (!listingDenied(source, parent, first.directory) || !sourceExact() ||
        !exactBytes(first.directory + "/payload", original)) return fail("backup-listing-denied");
    if (!partialWriteConflict(source, parent) || !sourceExact() || !Backup::Verify(first.directory).ok() ||
        !exactBytes(first.directory + "/payload", original)) return fail("backup-partial-write");
    const auto path = source + "/profiles/41.json";
    const auto h = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return fail("backup-lock");
    const auto blocked = Backup::Create(source, parent);
    CloseHandle(h);
    if (blocked.ok() || blocked.status != Backup::Status::SourceError || !sourceExact()) return fail("backup-read-lock");
#endif
    // Hard-linked source files are not accepted as private backup inputs.
    const auto alias = root + "/hardlink";
#ifdef Q_OS_WIN
    const auto linked = CreateHardLinkW(reinterpret_cast<LPCWSTR>(alias.utf16()),
        reinterpret_cast<LPCWSTR>((source + "/profiles/41.json").utf16()), nullptr);
#else
    const auto linked = ::link(QFile::encodeName(source + "/profiles/41.json").constData(), QFile::encodeName(alias).constData()) == 0;
#endif
    if (!linked) return fail("backup-link-create");
    const auto linkResult = Backup::Create(source, parent);
    if (!QFile::remove(alias) || linkResult.ok() || !sourceExact()) return fail("backup-link-refusal");
    // F2: supported maximum count and long names produce a manifest > old 1MiB.
    if (!QDir(root).mkdir("long")) return fail("backup-long-root");
    const auto longRoot = root + "/long";
    for (const auto &dir : Backup::Detail::Directories) if (!QDir(longRoot).mkdir(dir)) return fail("backup-long-dir");
    Manifest longFiles;
    for (int i = 0; i < Backup::Detail::MaxFiles; ++i) {
        const auto relative = "profiles/" + QString::number(i).rightJustified(4, '0') + QString(176, 'x');
        QFile file(longRoot + '/' + relative);
        if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly)) return fail("backup-long-file");
        file.close();
        longFiles.insert(relative, {});
    }
    const auto large = Backup::Create(longRoot, parent);
    QByteArray largeManifest;
    if (!large.ok() || !readManifest(large.directory + "/manifest.json", largeManifest) ||
        largeManifest.size() <= 1024 * 1024 || !exactBytes(large.directory + "/payload", longFiles) ||
        !exactBytes(longRoot, longFiles) || QJsonDocument::fromJson(largeManifest).object().value("entries").toArray().size() != longFiles.size() ||
        !spawn({"--legacy-migration-backup-verify-child", root, token, QFileInfo(large.directory).fileName(),
            QString::fromLatin1(Backup::Detail::hash(largeManifest))}, root, 0, "LEGACY_MIGRATION_BACKUP_REOPEN_PASS")) return fail("backup-long-manifest");
    QFile overflow(longRoot + "/profiles/overflow");
    if (!overflow.open(QIODevice::WriteOnly | QIODevice::NewOnly)) return fail("backup-overflow-file");
    overflow.close();
    if (Backup::Create(longRoot, parent).status != Backup::Status::SourceError || !QFile::remove(overflow.fileName()) ||
        !exactBytes(longRoot, longFiles)) return fail("backup-max-count");
    for (auto it = longFiles.begin(); it != longFiles.end(); ++it) {
        if (!QFile::remove(longRoot + '/' + it.key()) || !QFile::remove(large.directory + "/payload/" + it.key())) return fail("backup-long-cleanup");
    }
    for (const auto &dir : Backup::Detail::Directories) {
        if (!QDir().rmdir(longRoot + '/' + dir) || !QDir().rmdir(large.directory + "/payload/" + dir)) return fail("backup-long-dir-cleanup");
    }
    if (!QDir().rmdir(longRoot) || !QDir().rmdir(large.directory + "/payload") ||
        !QFile::remove(large.directory + "/manifest.json") || !QDir().rmdir(large.directory)) return fail("backup-long-root-cleanup");
    if (!Backup::Verify(first.directory).ok() || !Backup::Verify(second.directory).ok() ||
        !cleanupBackup(root, name) || !cleanupBackup(root, QFileInfo(second.directory).fileName())) return fail("backup-cleanup");
    for (auto it = original.begin(); it != original.end(); ++it) if (!QFile::remove(source + '/' + it.key())) return fail("backup-source-cleanup");
    for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
        if (!QDir().rmdir(source + '/' + dir)) return fail("backup-dir-cleanup");
    }
    if (!QDir().rmdir(source) || !QDir().rmdir(parent) || !QFile::remove(root + "/.owner") ||
        !QDir().rmdir(root) || QFileInfo::exists(root)) return fail("backup-root-cleanup");
    QTextStream(stdout) << "LEGACY_MIGRATION_BACKUP_PASS scope=legacy-directories restore=NOT_IMPLEMENTED\n";
    return 0;
}
} // namespace LegacyBackupFixture
