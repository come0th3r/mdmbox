#pragma once

#include "LegacyMigrationFixture.hpp"

// Characterization, not approval of legacy repair or transactional recovery.
// Every case starts from a new owned synthetic seed and disposable candidate.
namespace LegacyMigrationAdversarial {
using namespace LegacyMigrationFixture;

inline QStringList cases() {
    return {"malformed-profile", "invalid-type", "malformed-group", "orphan-profile",
            "duplicate-id", "duplicate-order", "write-lock"};
}

inline Manifest corpus(const QString &testCase) {
    auto files = seedFiles();
    auto objects = seedObjects();
    if (!cases().contains(testCase)) return {};
    if (testCase == "malformed-profile") files["profiles/205.json"] = "{synthetic-broken";
    else if (testCase == "malformed-group") files["groups/21.json"] = "{synthetic-broken";
    else {
        auto profile = objects.value("profiles/205.json").toObject();
        if (testCase == "invalid-type") profile["type"] = "synthetic-unknown";
        if (testCase == "orphan-profile") profile["gid"] = 999;
        if (testCase == "duplicate-id") profile["id"] = 41;
        files["profiles/205.json"] = QJsonDocument(profile).toJson();
        if (testCase == "duplicate-order") {
            auto group = objects.value("groups/7.json").toObject();
            group["order"] = QJsonArray{90, 90, 999, 103};
            files["groups/7.json"] = QJsonDocument(group).toJson();
            files["groups/pm.json"] = QJsonDocument(QJsonObject{{"groups", QJsonArray{12, 7, 12, 999, 34, 21}}}).toJson();
        }
    }
    return files;
}

inline QSet<QString> removed(const QString &testCase) {
    if (testCase == "malformed-profile" || testCase == "invalid-type") return {"profiles/205.json"};
    return {};
}

inline Manifest withMarker(Manifest files, const QString &token, const QString &role) {
    files.insert(RootFile, (token + ':' + role).toUtf8());
    return files;
}

inline Manifest afterLoad(const QString &testCase, const QString &token) {
    auto files = withMarker(corpus(testCase), token, "candidate");
    for (const auto &path : removed(testCase)) files.remove(path);
    return files;
}

inline bool loadSettings() {
    using namespace NekoGui;
    dataStore->flag_reorder = false;
    dataStore->fn = "groups/nekobox.json";
    dataStore->load_control_must = true;
    if (!dataStore->Load()) return false;
    dataStore->routing = std::make_unique<Routing>();
    dataStore->routing->fn = ROUTES_PREFIX + dataStore->active_routing;
    dataStore->routing->load_control_must = true;
    return dataStore->routing->Load();
}

inline bool observedGraph(const QString &testCase) {
    using namespace NekoGui;
    const auto payload = corpus(testCase);
    const bool deleted = !removed(testCase).isEmpty();
    const bool badGroup = testCase == "malformed-group";
    if (dataStore->flag_reorder || dataStore->started_id >= 0 ||
        profileManager->profiles.size() != (deleted ? 4 : 5) ||
        profileManager->groups.size() != (badGroup ? 3 : 4)) return false;
    const QList<int> tabs = badGroup ? QList<int>{12, 7, 34} :
        testCase == "duplicate-order" ? QList<int>{12, 7, 12, 34, 21} : QList<int>{12, 7, 34, 21};
    if (profileManager->groupsTabOrder != tabs) return false;
    const auto original = seedObjects();
    if (!containsFields(dataStore->ToJson(), original.value("groups/nekobox.json").toObject()) ||
        !containsFields(dataStore->routing->ToJson(), original.value(ROUTES_PREFIX + "SyntheticActive").toObject())) return false;
    for (const auto &[id, group] : profileManager->groups) {
        if (!group || group->id != id || group->fn != QStringLiteral("groups/%1.json").arg(id) ||
            !containsFields(group->ToJson(), QJsonDocument::fromJson(payload.value(group->fn)).object())) return false;
        QJsonArray ordered;
        for (const auto &profile : group->ProfilesWithOrder()) {
            if (!profile) return false;
            ordered.append(profile->id);
        }
        QJsonArray expected = QJsonDocument::fromJson(payload.value(group->fn)).object().value("order").toArray();
        if (deleted && id == 21) expected = {};
        if (testCase == "duplicate-order" && id == 7) expected = {90, 90, 103};
        if (testCase == "duplicate-id" && id == 21) expected = {41};
        if (ordered != expected) return false;
    }
    for (const auto &[key, profile] : profileManager->profiles) {
        if (!profile || !profile->bean || profile->fn != QStringLiteral("profiles/%1.json").arg(key) ||
            !containsFields(profile->ToJson(), QJsonDocument::fromJson(payload.value(profile->fn)).object())) return false;
    }
    if (badGroup && (profileManager->GetGroup(21) || !profileManager->GetProfile(205))) return false;
    if (testCase == "orphan-profile" && profileManager->GetProfile(205)->gid != 999) return false;
    if (testCase == "duplicate-id" && profileManager->GetProfile(205)->id != profileManager->GetProfile(41)->id) return false;
    return true;
}

inline bool lockedSave() {
#ifdef Q_OS_WIN
    using namespace NekoGui;
    const auto profile = profileManager->GetProfile(41);
    if (!profile || profile->latency != 17) return false;
    const auto path = QFileInfo(profile->fn).absoluteFilePath();
    if (!plainPath(path, false)) return false;
    // Deny new write handles even for an administrative build account. This
    // is not ACL manipulation or an injected replacement of production Save.
    const auto handle = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ,
                                    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    struct Close { HANDLE h; ~Close() { CloseHandle(h); } } close{handle};
    const auto probe = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const auto error = GetLastError();
    if (probe != INVALID_HANDLE_VALUE) { CloseHandle(probe); return false; }
    if (error != ERROR_SHARING_VIOLATION) return false;
    QByteArray before, after;
    if (!readFile(path, before)) return false;
    profile->latency = 88;
    const auto intended = profile->ToJsonBytes();
    const bool reportedChanged = profile->Save();
    // Save returns "changed", not successful I/O: prove both the misleading
    // return/cache update and exact preservation of the blocked disk file.
    return reportedChanged && profile->last_save_content == intended &&
        readFile(path, after) && after == before &&
        QJsonDocument::fromJson(after).object() != profile->ToJson();
#else
    return false; // Explicit Windows-only characterization; never fake PASS.
#endif
}

inline int child(const QStringList &args) {
    if (args.size() != 7 || !cases().contains(args[4])) return fail("edge-child-arguments", 64);
    const auto workspace = args[2], token = args[3], testCase = args[4], phase = args[5];
    const bool writeCase = testCase == "write-lock";
    if ((writeCase && !QStringList{"locked", "unrecovered", "retry", "recovered"}.contains(phase)) ||
        (!writeCase && phase != "first" && phase != "repeat")) return fail("edge-child-phase", 64);
    const auto absent = !writeCase && phase == "repeat" ? removed(testCase) : QSet<QString>{};
    Manifest before;
    if (!snapshot(workspace, "candidate", token, before, absent) ||
        QDir::currentPath() != QFileInfo(workspace + "/candidate").canonicalFilePath() ||
        digest(before) != args[6].toLatin1()) return fail("edge-root-guard", 64);
    auto expectedBefore = phase == "repeat" ? afterLoad(testCase, token) : withMarker(corpus(testCase), token, "candidate");
    if (writeCase && phase == "recovered") {
        // All other files remain exact synthetic bytes. The only changed file
        // must preserve every supplied field except the intentional latency.
        const auto saved = QJsonDocument::fromJson(before.value("profiles/41.json"));
        auto expected = seedObjects().value("profiles/41.json").toObject();
        expected["yc"] = 88;
        if (!saved.isObject() || !containsFields(saved.object(), expected)) return fail("edge-recovered-input", 64);
        expectedBefore["profiles/41.json"] = before.value("profiles/41.json");
    }
    if (before != expectedBefore) return fail("edge-not-synthetic", 64);
    int dialogs = 0;
    MW_show_log = [](QString) {};
    MW_dialog_message = [&dialogs](QString, QString) { ++dialogs; };
    struct Reset { ~Reset() { MW_dialog_message = [](QString, QString) {}; } } reset;
    if (!loadSettings()) return fail("edge-settings");
    NekoGui::profileManager->LoadManager();
    Manifest loaded;
    if (dialogs || !snapshot(workspace, "candidate", token, loaded, removed(testCase))) return fail("edge-load-snapshot");
    if (!writeCase) {
        if (loaded != afterLoad(testCase, token) || !observedGraph(testCase)) return fail("edge-unexpected-behavior");
    } else {
        using namespace NekoGui;
        if (loaded != before) return fail("edge-write-load-mutated");
        if (phase == "recovered") {
            auto profile = profileManager->GetProfile(41);
            if (!profile || profile->latency != 88 ||
                QJsonDocument::fromJson(before.value(profile->fn)).object() != profile->ToJson()) return fail("edge-recovery-reopen");
            profile->latency = 17; // Only normalize the in-memory assertion view.
        }
        if (!semanticGraph()) return fail("edge-write-graph");
        if (phase == "locked" && !lockedSave()) return fail("edge-lock-not-observed");
        if (phase == "retry") {
            auto profile = profileManager->GetProfile(41);
            profile->latency = 88;
            profile->Save();
            Manifest saved;
            if (!snapshot(workspace, "candidate", token, saved) ||
                QJsonDocument::fromJson(saved.value(profile->fn)).object() != profile->ToJson()) return fail("edge-retry-readback");
            auto allowed = before;
            allowed[profile->fn] = saved.value(profile->fn);
            if (saved != allowed || saved == before) return fail("edge-retry-unrelated");
        } else {
            Manifest after;
            if (!snapshot(workspace, "candidate", token, after) || after != before) return fail("edge-unexpected-write");
        }
    }
    QTextStream(stdout) << "LEGACY_MIGRATION_EDGE_CHILD_OBSERVED case=" << testCase << " phase=" << phase << '\n';
    return 0;
}

inline int runCase(const QString &testCase) {
    QTemporaryDir directory(QDir::tempPath() + "/mdmbox-legacy-migration-XXXXXX");
    directory.setAutoRemove(false);
    if (!directory.isValid() || !plainPath(directory.path(), true)) return fail("edge-workspace");
    const auto workspace = QFileInfo(directory.path()).canonicalFilePath();
    const auto token = QUuid::createUuid().toString(QUuid::Id128);
    if (!writeNew(workspace + '/' + OwnerFile, token.toUtf8())) return fail("edge-owner");
    for (const auto &role : {QStringLiteral("seed"), QStringLiteral("candidate")}) {
        const auto root = workspace + '/' + role;
        if (!QDir().mkdir(root) || !writeNew(root + '/' + RootFile, (token + ':' + role).toUtf8())) return fail("edge-create");
        for (const auto &dir : {QStringLiteral("groups"), QStringLiteral("profiles"), ROUTES_PREFIX_NAME}) {
            if (!QDir().mkdir(root + '/' + dir)) return fail("edge-dir");
        }
        // Seed is always the complete immutable valid-root recovery reference.
        const auto files = role == "seed" ? seedFiles() : corpus(testCase);
        if (files.size() != 14) return fail("edge-corpus");
        for (auto it = files.begin(); it != files.end(); ++it) {
            if (!writeNew(root + '/' + it.key(), it.value())) return fail("edge-write");
        }
    }
    Manifest originalSeed, current;
    if (!snapshot(workspace, "seed", token, originalSeed) || !snapshot(workspace, "candidate", token, current)) return fail("edge-initial");
    const QStringList phases = testCase == "write-lock" ? QStringList{"locked", "unrecovered", "retry", "recovered"} : QStringList{"first", "repeat"};
    const auto initialArgs = QStringList{"--legacy-migration-edge-child", workspace, token, testCase, phases.first(), QString::fromLatin1(digest(current))};
    QList<QStringList> rejected;
    auto wrongToken = initialArgs; wrongToken[2] = QString(32, QLatin1Char('0')); rejected.append(wrongToken);
    auto wrongDigest = initialArgs; wrongDigest[5] = QString(64, QLatin1Char('0')); rejected.append(wrongDigest);
    auto wrongRoot = initialArgs; wrongRoot[1] = workspace + "/seed"; rejected.append(wrongRoot);
    auto extra = initialArgs; extra.append("-flag_reorder"); rejected.append(extra);
    for (const auto &arguments : rejected) {
        if (!spawn(arguments, workspace + "/candidate", 64, QByteArray("LEGACY_MIGRATION_FAIL"))) return fail("edge-negative-guard");
        Manifest seed, candidate;
        if (!snapshot(workspace, "seed", token, seed) || seed != originalSeed ||
            !snapshot(workspace, "candidate", token, candidate) || candidate != current) return fail("edge-negative-mutated");
    }
    // Correct token/root/digest but a different exact synthetic corpus: the
    // digest capability alone must never authorize arbitrary loader input.
    auto wrongCorpus = initialArgs;
    wrongCorpus[3] = testCase == "malformed-profile" ? "invalid-type" : "malformed-profile";
    wrongCorpus[4] = "first";
    if (!spawn(wrongCorpus, workspace + "/candidate", 64, QByteArray("LEGACY_MIGRATION_FAIL edge-not-synthetic"))) return fail("edge-corpus-guard");
    Manifest guardedSeed, guardedCandidate;
    if (!snapshot(workspace, "seed", token, guardedSeed) || guardedSeed != originalSeed ||
        !snapshot(workspace, "candidate", token, guardedCandidate) || guardedCandidate != current) return fail("edge-corpus-mutated");
    for (const auto &phase : phases) {
        const auto args = QStringList{"--legacy-migration-edge-child", workspace, token, testCase, phase, QString::fromLatin1(digest(current))};
        const auto marker = ("LEGACY_MIGRATION_EDGE_CHILD_OBSERVED case=" + testCase + " phase=" + phase).toUtf8();
        if (!spawn(args, workspace + "/candidate", 0, marker)) return fail("edge-child");
        Manifest seed, next;
        if (!snapshot(workspace, "seed", token, seed) || seed != originalSeed ||
            !snapshot(workspace, "candidate", token, next, removed(testCase))) return fail("edge-parent-manifest");
        if (testCase != "write-lock") {
            if (next != afterLoad(testCase, token)) return fail("edge-parent-delta");
        } else if (phase == "retry") {
            auto allowed = current;
            allowed["profiles/41.json"] = next.value("profiles/41.json");
            if (next != allowed || next == current) return fail("edge-parent-retry");
        } else if (next != current) return fail("edge-parent-unexpected-write");
        current = next;
    }
    if (!cleanup(workspace, token, removed(testCase)) || QFileInfo::exists(workspace)) return fail("edge-cleanup");
    QTextStream(stdout) << "LEGACY_MIGRATION_EDGE_OBSERVED case=" << testCase << " acceptance=NOT_ACCEPTED\n";
    return 0;
}

inline int run(QCoreApplication &app) {
    const auto args = app.arguments();
    if (args.size() > 1 && args[1] == "--legacy-migration-edge-child") return child(args);
    if (args != QStringList{args.first(), "--legacy-migration-adversarial"}) return fail("edge-parent-arguments", 64);
    for (const auto &testCase : cases()) if (runCase(testCase) != 0) return 1;
    QTextStream(stdout) << "LEGACY_MIGRATION_ADVERSARIAL_OBSERVATIONS_COMPLETE cases=7 children=16 guards=35 acceptance=NOT_ACCEPTED\n";
    return 0;
}
} // namespace LegacyMigrationAdversarial
