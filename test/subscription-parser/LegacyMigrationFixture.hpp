#pragma once

#include "db/Database.hpp"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QTemporaryDir>
#include <QTextStream>
#include <QUuid>
#ifdef Q_OS_WIN
#include <qt_windows.h>
#else
#include <sys/stat.h>
#endif

// Test-only, compiled by the existing production-graph parser runner. No current
// Add/Import API is used to construct this historical-shaped JSON corpus.
namespace LegacyMigrationFixture {
inline constexpr char SeedJson[] = R"fixture({
  "groups/pm.json": {"groups":[12,7,34,21]},
  "groups/nekobox.json": {
    "current_group":12, "mdmbox_selected_id":103, "remember_id":41,
    "remember_enable":false, "active_routing":"SyntheticActive",
    "vpn_bypass_process":"synthetic.exe\nanother.exe",
    "vpn_bypass_cidr":"127.0.0.0/8\n192.0.2.0/24", "vpn_rule_white":true
  },
  "groups/7.json": {
    "id":7, "name":"synthetic-seven", "order":[90,41],
    "archive":false, "skip_auto_update":true, "front_proxy_id":103,
    "url":"https://subscription.invalid/synthetic?format=clash&case=old",
    "info":"synthetic \u043c\u0435\u0442\u0430\u0434\u0430\u043d\u043d\u044b\u0435", "lastup":4294967297
  },
  "groups/12.json": {
    "id":12, "name":"synthetic-twelve", "order":[103],
    "archive":true, "skip_auto_update":false, "front_proxy_id":90,
    "subscription_kind":"links", "info":"synthetic-12", "lastup":1700000012
  },
  "groups/21.json": {
    "id":21, "name":"synthetic-twenty-one", "order":[205],
    "archive":true, "skip_auto_update":true, "front_proxy_id":-1,
    "subscription_kind":"links", "info":"synthetic-21", "lastup":1700000021
  },
  "groups/34.json": {
    "id":34, "name":"synthetic-thirty-four", "order":[402],
    "archive":false, "skip_auto_update":false, "front_proxy_id":-1,
    "subscription_kind":"links", "info":"synthetic-34", "lastup":1700000034
  },
  "profiles/41.json": {"type":"socks", "id":41, "gid":7, "yc":17,
    "bean":{"_v":0, "v":5, "name":"same-synthetic-name", "addr":"127.0.0.1", "port":18041}},
  "profiles/90.json": {"type":"socks", "id":90, "gid":7, "yc":29,
    "bean":{"_v":0, "v":5, "name":"same-synthetic-name", "addr":"127.0.0.1", "port":18090}},
  "profiles/103.json": {"type":"http", "id":103, "gid":12,
    "bean":{"_v":0, "v":-80, "name":"synthetic-http", "addr":"127.0.0.1", "port":18103}},
  "profiles/205.json": {"type":"socks", "id":205, "gid":21,
    "bean":{"_v":0, "v":5, "name":"synthetic-205", "addr":"127.0.0.1", "port":18205}},
  "profiles/402.json": {"type":"http", "id":402, "gid":34,
    "bean":{"_v":0, "v":-80, "name":"synthetic-402", "addr":"127.0.0.1", "port":18402}},
  "routes_box/SyntheticActive": {
    "def_outbound":"proxy", "remote_dns":"udp://127.0.0.1:15353",
    "direct_dns":"udp://127.0.0.1:15354", "dns_routing":true,
    "custom":"{\"rules\":[{\"domain\":[\"first.invalid\"],\"outbound\":\"proxy\"},{\"ip_cidr\":[\"192.0.2.0/24\"],\"outbound\":\"direct\"}]}",
    "mdmbox_rules_json":"[{\"type\":\"domain\",\"value\":\"first.invalid\"},{\"type\":\"process\",\"value\":\"synthetic.exe\"}]"
  },
  "routes_box/SyntheticInactive": {"def_outbound":"direct", "custom":"{\"rules\":[]}"}
})fixture";

using Manifest = QMap<QString, QByteArray>;
inline const QString OwnerFile = QStringLiteral(".mdmbox-migration-owner");
inline const QString RootFile = QStringLiteral(".mdmbox-migration-root");

inline int fail(const char *code, int status = 1) {
    QTextStream(stderr) << "LEGACY_MIGRATION_FAIL " << code << '\n';
    return status; // No profile contents, tokens or URLs in diagnostics.
}

inline bool plainPath(const QString &path, bool directory) {
    QFileInfo leaf(path);
    if (!leaf.exists() || (directory ? !leaf.isDir() : !leaf.isFile())) return false;
    for (QFileInfo info(leaf.absoluteFilePath());;) {
        if (!info.exists() || info.isSymLink()) return false;
#ifdef Q_OS_WIN
        const auto attributes = GetFileAttributesW(reinterpret_cast<LPCWSTR>(info.absoluteFilePath().utf16()));
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
#endif
        // A regular hard link can escape the owned tree without being a
        // symlink/reparse point. Production Save truncates the same inode.
        if (info.isFile()) {
#ifdef Q_OS_WIN
            const auto handle = CreateFileW(reinterpret_cast<LPCWSTR>(info.absoluteFilePath().utf16()),
                                            FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (handle == INVALID_HANDLE_VALUE) return false;
            BY_HANDLE_FILE_INFORMATION details{};
            const auto ok = GetFileInformationByHandle(handle, &details);
            CloseHandle(handle);
            if (!ok || details.nNumberOfLinks != 1 || (details.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
#else
            struct stat details{};
            const auto native = QFile::encodeName(info.absoluteFilePath());
            if (::lstat(native.constData(), &details) != 0 || details.st_nlink != 1) return false;
#endif
        }
        const auto canonical = info.canonicalFilePath();
        if (canonical.isEmpty()) return false;
#ifdef Q_OS_WIN
        if (canonical.compare(info.absoluteFilePath(), Qt::CaseInsensitive) != 0) return false;
#else
        if (canonical != info.absoluteFilePath()) return false;
#endif
        const auto parent = info.dir().absolutePath();
        if (parent == info.absoluteFilePath()) break;
        info.setFile(parent);
    }
    return true;
}

inline bool readFile(const QString &path, QByteArray &bytes) {
    if (!plainPath(path, false) || QFileInfo(path).size() > 65536) return false;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;
    bytes = file.readAll();
    return file.error() == QFileDevice::NoError;
}

inline bool writeNew(const QString &path, const QByteArray &bytes) {
    if (!plainPath(QFileInfo(path).absolutePath(), true) || QFileInfo::exists(path)) return false;
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly) || file.write(bytes) != bytes.size() || !file.flush()) return false;
    file.close();
    QByteArray saved;
    return readFile(path, saved) && saved == bytes;
}

inline QJsonObject seedObjects() {
    QJsonParseError error{};
    const auto doc = QJsonDocument::fromJson(QByteArray(SeedJson), &error);
    return error.error == QJsonParseError::NoError && doc.isObject() ? doc.object() : QJsonObject{};
}

inline Manifest seedFiles() {
    Manifest result;
    const auto objects = seedObjects();
    for (auto it = objects.begin(); it != objects.end(); ++it) {
        if (!it.value().isObject()) return {};
        result.insert(it.key(), QJsonDocument(it.value().toObject()).toJson());
    }
    result.insert(QStringLiteral("preservation.txt"), QByteArray("synthetic-original-sentinel\n"));
    return result;
}

inline QByteArray digest(const Manifest &files) {
    QCryptographicHash hash(QCryptographicHash::Sha256);
    for (auto it = files.begin(); it != files.end(); ++it) {
        const auto key = it.key().toUtf8();
        hash.addData(QByteArray::number(key.size()) + ':' + key);
        hash.addData(QByteArray::number(it.value().size()) + ':' + it.value());
    }
    return hash.result().toHex();
}

inline bool ownedWorkspace(const QString &workspace, const QString &token) {
    if (!QRegularExpression(QStringLiteral("^[0-9a-f]{32}$")).match(token).hasMatch() ||
        !plainPath(workspace, true)) return false;
    const QFileInfo info(workspace);
    const auto temp = QFileInfo(QDir::tempPath()).canonicalFilePath();
    if (info.dir().canonicalPath() != temp ||
        !info.fileName().startsWith(QStringLiteral("mdmbox-legacy-migration-"))) return false;
    const auto names = QDir(workspace).entryList(QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);
    if (QSet<QString>(names.begin(), names.end()) != QSet<QString>{OwnerFile, QStringLiteral("seed"), QStringLiteral("candidate")}) return false;
    QByteArray marker;
    return readFile(workspace + '/' + OwnerFile, marker) && marker == token.toUtf8();
}

inline bool snapshot(const QString &workspace, const QString &role, const QString &token, Manifest &out,
                     const QSet<QString> &absent = {}) {
    out.clear();
    if (!ownedWorkspace(workspace, token) || (role != "seed" && role != "candidate")) return false;
    // The adversarial corpus permits exactly one production-loader deletion.
    // Never relax the valid-root or immutable-seed allowlist.
    if (!absent.isEmpty() && (role != "candidate" || absent != QSet<QString>{"profiles/205.json"})) return false;
    const auto root = workspace + '/' + role;
    if (!plainPath(root, true)) return false;
    const auto payload = seedFiles();
    if (payload.size() != 14) return false;
    QSet<QString> wanted;
    for (auto it = payload.begin(); it != payload.end(); ++it) wanted.insert(it.key());
    for (const auto &file : absent) {
        if (!wanted.remove(file)) return false;
    }
    wanted.insert(RootFile);
    const QStringList dirs{QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME};
    for (const auto &entry : QDir(root).entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot)) {
        if (entry.isDir()) {
            if (!dirs.contains(entry.fileName()) || !plainPath(entry.absoluteFilePath(), true)) return false;
            for (const auto &file : QDir(entry.absoluteFilePath()).entryInfoList(QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot)) {
                const auto relative = entry.fileName() + '/' + file.fileName();
                QByteArray bytes;
                if (!wanted.contains(relative) || !readFile(file.absoluteFilePath(), bytes)) return false;
                out.insert(relative, bytes);
            }
        } else {
            QByteArray bytes;
            if (!wanted.contains(entry.fileName()) || !readFile(entry.absoluteFilePath(), bytes)) return false;
            out.insert(entry.fileName(), bytes);
        }
    }
    if (out.size() != wanted.size() || out.value(RootFile) != (token + ':' + role).toUtf8()) return false;
    for (const auto &dir : dirs) if (!plainPath(root + '/' + dir, true)) return false;
    return true;
}

// Compare every supplied field recursively, while allowing serializer defaults
// absent from the historical-shaped seed. Arrays and strings remain exact.
inline bool containsFields(const QJsonObject &actual, const QJsonObject &expected) {
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        if (!actual.contains(it.key())) return false;
        const auto value = actual.value(it.key());
        if (it.value().isObject()) {
            if (!value.isObject() || !containsFields(value.toObject(), it.value().toObject())) return false;
        } else if (value != it.value()) return false;
    }
    return true;
}

inline bool syntheticFields(const Manifest &files) {
    const auto expected = seedObjects();
    if (expected.size() != 13) return false;
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        QJsonParseError error{};
        const auto doc = QJsonDocument::fromJson(files.value(it.key()), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject() ||
            !containsFields(doc.object(), it.value().toObject())) return false;
    }
    return files.value("preservation.txt") == seedFiles().value("preservation.txt");
}

inline bool semanticGraph() {
    using namespace NekoGui;
    const auto expected = seedObjects();
    if (dataStore->flag_reorder || dataStore->started_id >= 0 ||
        profileManager->groups.size() != 4 || profileManager->profiles.size() != 5 ||
        profileManager->groupsTabOrder != QList<int>{12, 7, 34, 21} ||
        !containsFields(dataStore->ToJson(), expected.value("groups/nekobox.json").toObject()) ||
        !dataStore->routing || dataStore->routing->fn != ROUTES_PREFIX + dataStore->active_routing ||
        !containsFields(dataStore->routing->ToJson(), expected.value(ROUTES_PREFIX + "SyntheticActive").toObject())) return false;
    QSet<int> seen;
    for (const auto &[id, group] : profileManager->groups) {
        if (!group || group->id != id || group->fn != QStringLiteral("groups/%1.json").arg(id) ||
            group->subscription_kind != "links" ||
            !containsFields(group->ToJson(), expected.value(group->fn).toObject())) return false;
        QJsonArray actualOrder;
        for (const auto &profile : group->ProfilesWithOrder()) {
            if (!profile || profile->gid != id || seen.contains(profile->id)) return false;
            seen.insert(profile->id);
            actualOrder.append(profile->id);
        }
        if (actualOrder != expected.value(group->fn).toObject().value("order").toArray()) return false;
        if (group->front_proxy_id >= 0 && !profileManager->GetProfile(group->front_proxy_id)) return false;
    }
    if (seen.size() != 5 || !profileManager->CurrentGroup() || profileManager->CurrentGroup()->id != 12 ||
        !profileManager->GetProfile(dataStore->selected_id) || dataStore->selected_id != 103 ||
        !profileManager->GetProfile(dataStore->remember_id) || dataStore->remember_id != 41) return false;
    for (const auto &[id, profile] : profileManager->profiles) {
        if (!profile || !profile->bean || profile->id != id ||
            profile->fn != QStringLiteral("profiles/%1.json").arg(id) ||
            !containsFields(profile->ToJson(), expected.value(profile->fn).toObject())) return false;
    }
    return profileManager->GetGroup(7)->sub_last_update == Q_INT64_C(4294967297);
}

inline QMap<QString, QJsonObject> serializedGraph() {
    using namespace NekoGui;
    QMap<QString, QJsonObject> expected;
    for (const auto &[id, profile] : profileManager->profiles) expected.insert(profile->fn, profile->ToJson());
    for (const auto &[id, group] : profileManager->groups) expected.insert(group->fn, group->ToJson());
    expected.insert(dataStore->fn, dataStore->ToJson());
    expected.insert(dataStore->routing->fn, dataStore->routing->ToJson());
    // ProfileManager privately inherits JsonStore; its single registered item
    // is groupsTabOrder (Database.cpp). Validate the complete manager JSON too.
    QJsonArray tabs;
    for (auto id : profileManager->groupsTabOrder) tabs.append(id);
    expected.insert(QStringLiteral("groups/pm.json"), QJsonObject{{QStringLiteral("groups"), tabs}});
    return expected;
}

inline bool matchesSerializedGraph(const Manifest &files, const QMap<QString, QJsonObject> &expected) {
    if (expected.size() != 12) return false;
    for (auto it = expected.begin(); it != expected.end(); ++it) {
        QJsonParseError error{};
        const auto doc = QJsonDocument::fromJson(files.value(it.key()), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject() || doc.object() != it.value()) return false;
    }
    return true;
}

inline int runChild(const QStringList &args) {
    // No cwd change and no loader call until all capability/path checks pass.
    if (args.size() != 6 || (args[4] != "save" && args[4] != "reopen")) return fail("child-arguments", 64);
    const auto workspace = args[2];
    const auto token = args[3];
    Manifest before;
    if (!snapshot(workspace, QStringLiteral("candidate"), token, before) ||
        QDir::currentPath() != QFileInfo(workspace + "/candidate").canonicalFilePath() ||
        digest(before) != args[5].toLatin1() ||
        !syntheticFields(before)) return fail("child-root-guard", 64);
    if (args[4] == "save") {
        auto original = seedFiles();
        original.insert(RootFile, (token + ":candidate").toUtf8());
        if (before != original) return fail("child-not-synthetic-seed", 64);
    }
    int dialogs = 0;
    MW_show_log = [](QString) {};
    MW_dialog_message = [&dialogs](QString, QString) { ++dialogs; };
    struct ResetSinks {
        ~ResetSinks() { MW_dialog_message = [](QString, QString) {}; }
    } resetSinks;
    using namespace NekoGui;
    dataStore->flag_reorder = false;
    dataStore->fn = QStringLiteral("groups/nekobox.json");
    dataStore->load_control_must = true;
    if (!dataStore->Load()) return fail("settings-load");
    // Use the production Routing loader, not SetToActive (which saves settings
    // while selecting). The inactive route must remain untouched.
    dataStore->routing = std::make_unique<Routing>();
    dataStore->routing->fn = ROUTES_PREFIX + dataStore->active_routing;
    dataStore->routing->load_control_must = true;
    if (!dataStore->routing->Load()) return fail("routing-load");
    profileManager->LoadManager();
    Manifest loaded;
    if (dialogs || !semanticGraph() || !snapshot(workspace, "candidate", token, loaded) || loaded != before) return fail("load-preservation");
    const auto expectedSaved = serializedGraph();
    if (args[4] == "reopen" && !matchesSerializedGraph(before, expectedSaved)) return fail("reopen-serialization");
    if (args[4] == "save") {
        // Negative oracle: a no-op Save must not pass the same readback check.
        // The seed intentionally lacks subscription_kind and other defaults.
        if (matchesSerializedGraph(before, expectedSaved)) return fail("save-oracle-noop");
        for (const auto &[id, profile] : profileManager->profiles) profile->Save();
        for (const auto &[id, group] : profileManager->groups) group->Save();
        profileManager->SaveManager();
        dataStore->routing->Save();
        dataStore->Save();
        Manifest saved;
        if (dialogs || !semanticGraph() || !snapshot(workspace, "candidate", token, saved)) return fail("save-graph");
        if (!syntheticFields(saved) || !matchesSerializedGraph(saved, expectedSaved)) return fail("save-readback");
        if (saved.value(ROUTES_PREFIX + "SyntheticInactive") != before.value(ROUTES_PREFIX + "SyntheticInactive") ||
            saved.value("preservation.txt") != before.value("preservation.txt")) return fail("save-unrelated-file");
    }
    QTextStream(stdout) << "LEGACY_MIGRATION_CHILD_PASS phase=" << args[4] << '\n';
    return 0;
}

inline bool spawn(const QStringList &args, const QString &cwd, int expected, const QByteArray &marker) {
    QProcess child;
    child.setWorkingDirectory(cwd);
    child.setProcessChannelMode(QProcess::MergedChannels);
    child.start(QCoreApplication::applicationFilePath(), args);
    if (!child.waitForStarted(10000)) return false;
    if (!child.waitForFinished(30000)) {
        child.kill();
        child.waitForFinished(5000);
        return false;
    }
    const auto output = child.readAll();
    // Deliberately don't forward arbitrary child output/profile contents.
    const auto lines = output.split('\n');
    bool matched = false;
    for (auto line : lines) {
        if (line.endsWith('\r')) line.chop(1);
        if (line == marker) matched = true;
    }
    return child.exitStatus() == QProcess::NormalExit && child.exitCode() == expected &&
        (expected == 0 ? matched && !output.contains("LEGACY_MIGRATION_FAIL") : output.contains(marker));
}

inline bool cleanup(const QString &workspace, const QString &token, const QSet<QString> &candidateAbsent = {}) {
    Manifest seed, candidate;
    if (!snapshot(workspace, "seed", token, seed) || !snapshot(workspace, "candidate", token, candidate, candidateAbsent)) return false;
    // Explicit, allowlisted removal only. Never use recursive removal, and
    // never traverse an unexpected directory, even on an error path.
    for (const auto &role : {QStringLiteral("seed"), QStringLiteral("candidate")}) {
        const auto root = workspace + '/' + role;
        const auto files = role == "seed" ? seed : candidate;
        for (auto it = files.begin(); it != files.end(); ++it) {
            const auto file = root + '/' + it.key();
            if (!plainPath(file, false) || !QFile::remove(file)) return false;
        }
        for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
            if (!plainPath(root + '/' + dir, true) || !QDir().rmdir(root + '/' + dir)) return false;
        }
        if (!plainPath(root, true) || !QDir().rmdir(root)) return false;
    }
    return plainPath(workspace, true) && QFile::remove(workspace + '/' + OwnerFile) && QDir().rmdir(workspace);
}

inline int run(QCoreApplication &app) {
    const auto args = app.arguments();
    if (args.size() > 1 && args[1] == "--legacy-migration-child") return runChild(args);
    if (args != QStringList{args.first(), QStringLiteral("--legacy-migration")}) return fail("parent-arguments", 64);
    QTemporaryDir directory(QDir::tempPath() + QStringLiteral("/mdmbox-legacy-migration-XXXXXX"));
    directory.setAutoRemove(false); // Failed validation retains only our synthetic workspace.
    if (!directory.isValid() || !plainPath(directory.path(), true)) return fail("workspace-create");
    const auto workspace = QFileInfo(directory.path()).canonicalFilePath();
    const auto token = QUuid::createUuid().toString(QUuid::Id128);
    const auto files = seedFiles();
    if (files.size() != 14 || !writeNew(workspace + '/' + OwnerFile, token.toUtf8())) return fail("workspace-marker");
    for (const auto &role : {QStringLiteral("seed"), QStringLiteral("candidate")}) {
        const auto root = workspace + '/' + role;
        if (!QDir().mkdir(root) || !writeNew(root + '/' + RootFile, (token + ':' + role).toUtf8())) return fail("root-create");
        for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
            if (!QDir().mkdir(root + '/' + dir)) return fail("root-directory");
        }
        for (auto it = files.begin(); it != files.end(); ++it) {
            if (role == "seed") {
                if (!writeNew(root + '/' + it.key(), it.value())) return fail("seed-write");
            } else if (!QFile::copy(workspace + "/seed/" + it.key(), root + '/' + it.key())) return fail("clone-copy");
        }
    }
    Manifest originalSeed, originalCandidate;
    if (!snapshot(workspace, "seed", token, originalSeed) || !snapshot(workspace, "candidate", token, originalCandidate)) return fail("initial-manifest");
    const auto candidate = workspace + QStringLiteral("/candidate");
    const auto childArgs = QStringList{QStringLiteral("--legacy-migration-child"), workspace, token, QStringLiteral("save"), QString::fromLatin1(digest(originalCandidate))};
    QList<QStringList> rejected;
    auto wrongToken = childArgs; wrongToken[2] = QString(32, QLatin1Char('0')); rejected.append(wrongToken);
    auto wrongDigest = childArgs; wrongDigest[4] = QString(64, QLatin1Char('0')); rejected.append(wrongDigest);
    auto wrongRoot = childArgs; wrongRoot[1] = workspace + QStringLiteral("/seed"); rejected.append(wrongRoot);
    auto extra = childArgs; extra.append(QStringLiteral("-flag_reorder")); rejected.append(extra);
    for (const auto &arguments : rejected) {
        if (!spawn(arguments, candidate, 64, QByteArray("LEGACY_MIGRATION_FAIL"))) return fail("negative-guard");
        Manifest seed, clone;
        if (!snapshot(workspace, "seed", token, seed) || !snapshot(workspace, "candidate", token, clone) || seed != originalSeed || clone != originalCandidate) return fail("negative-mutated-root");
    }
    if (!spawn(childArgs, candidate, 0, QByteArray("LEGACY_MIGRATION_CHILD_PASS phase=save"))) return fail("save-child");
    Manifest seed, saved;
    if (!snapshot(workspace, "seed", token, seed) || seed != originalSeed || !snapshot(workspace, "candidate", token, saved)) return fail("first-reopen-manifest");
    auto reopenArgs = childArgs; reopenArgs[3] = QStringLiteral("reopen"); reopenArgs[4] = QString::fromLatin1(digest(saved));
    if (!spawn(reopenArgs, candidate, 0, QByteArray("LEGACY_MIGRATION_CHILD_PASS phase=reopen"))) return fail("reopen-child");
    Manifest reopened;
    if (!snapshot(workspace, "seed", token, seed) || seed != originalSeed || !snapshot(workspace, "candidate", token, reopened) || reopened != saved) return fail("second-reopen-manifest");
    if (!cleanup(workspace, token) || QFileInfo::exists(workspace)) return fail("owned-cleanup");
    QTextStream(stdout) << "LEGACY_MIGRATION_VALID_ROOT_REOPEN_PASS children=2 guards=4 seed_files=15\n";
    return 0;
}
} // namespace LegacyMigrationFixture
