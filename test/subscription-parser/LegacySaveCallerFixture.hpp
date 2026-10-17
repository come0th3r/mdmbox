#pragma once

#include "LegacyMigrationAdversarial.hpp"
#include "ui/mainwindow.h"
#include "ui/edit/dialog_edit_profile.h"
#include <QApplication>
#include <QLineEdit>
#include <QMessageBox>
#include <QTimer>
#include <QEventLoop>

namespace LegacySaveCallerFixture {
using namespace LegacyMigrationFixture;

// Close every modal with a negative answer: even a regression must never start
// a core, exit/relaunch the program or enable an OS mode in this fixture.
class DialogObserver {
    QTimer timer;
public:
    int warnings = 0, questions = 0, unexpected = 0;
    QString lastText;
    DialogObserver() {
        QObject::connect(&timer, &QTimer::timeout, [&] {
            for (auto *widget : QApplication::topLevelWidgets()) {
                auto *box = qobject_cast<QMessageBox *>(widget);
                if (!box || !box->isVisible()) continue;
                lastText = box->text();
                if (box->windowTitle() == "Save failed") ++warnings;
                else if (box->icon() == QMessageBox::Question) ++questions;
                else ++unexpected;
                box->done(QMessageBox::No);
            }
        });
        timer.start(1);
    }
    void reset() { warnings = questions = unexpected = 0; lastText.clear(); }
};

inline int child(QApplication &app) {
    using namespace NekoGui;
    const auto args = app.arguments();
    Manifest before;
    if (args.size() != 5 || !snapshot(args[2], "candidate", args[3], before) ||
        digest(before) != args[4].toLatin1() ||
        QFileInfo(QDir::currentPath()).canonicalFilePath() != args[2] + "/candidate") return fail("caller-child-guard", 64);
    if (!LegacyMigrationAdversarial::loadSettings()) return fail("caller-load");
    dataStore->flag_tray = true;
    dataStore->hotkey_mainwindow.clear(); dataStore->hotkey_group.clear();
    dataStore->hotkey_route.clear(); dataStore->hotkey_system_proxy_menu.clear();
    MW_show_log = [](QString) {};
    MainWindow window;
    DialogObserver observer;
    // Real production dispatcher, queued through its installed callback.
    const auto dispatch = [&](const QString &info) {
        MW_dialog_message("synthetic-save-caller", info);
        QEventLoop events;
        QTimer::singleShot(100, &events, &QEventLoop::quit);
        events.exec();
    };
    const auto oldSettings = before.value("groups/nekobox.json");
    const auto settingsCache = dataStore->last_save_content;
    dataStore->inbound_socks_port = 19081;
    dataStore->started_id = 41;
    // Open failure uses a real absent parent, with no ACL/token assumptions.
    const auto settingsPath = dataStore->fn;
    dataStore->fn = "absent/settings.json";
    dispatch("UpdateDataStore,RouteChanged,VPNChanged,NeedRestart");
    QByteArray bytes;
    if (observer.warnings != 1 || observer.questions || observer.unexpected ||
        observer.lastText.contains(dataStore->fn) || dataStore->last_save_content != settingsCache ||
        !readFile(settingsPath, bytes) || bytes != oldSettings || QFileInfo::exists("absent")) return fail("caller-settings-open");
    dataStore->fn = settingsPath;
    observer.reset();
    dataStore->save_control_no_save = true;
    dispatch("UpdateDataStore,RouteChanged,NeedRestart");
    if (observer.warnings != 1 || observer.questions || observer.unexpected ||
        dataStore->last_save_content != settingsCache || !readFile(settingsPath, bytes) || bytes != oldSettings) return fail("caller-settings-disabled");
    dataStore->save_control_no_save = false;
    observer.reset();
    dispatch("UpdateDataStore");
    if (observer.warnings || observer.questions != 1 || observer.unexpected ||
        !readFile(settingsPath, bytes) || bytes != dataStore->ToJsonBytes() || bytes == oldSettings) return fail("caller-settings-retry");
    observer.reset();
    dispatch("UpdateDataStore");
    if (observer.warnings || observer.questions || observer.unexpected) return fail("caller-settings-unchanged");

    // Profile editor uses the real production accept(), not a mock save helper.
    const auto live = profileManager->GetProfile(41);
    const auto liveBefore = live->ToJson();
    const auto profileBytes = before.value(live->fn);
    const auto profileCache = live->last_save_content;
    QStringList messages;
    MW_dialog_message = [&](QString sender, QString message) {
        if (sender == Dialog_DialogEditProfile) messages.append(message);
        else messages.append("unexpected");
    };
    {
        DialogEditProfile cancelled("", 41, &window);
        auto *name = cancelled.findChild<QLineEdit *>("name");
        if (!name) return fail("caller-editor-name");
        name->setText("synthetic-cancelled-edit");
        // Constructor queues adjust/show callbacks. Let them complete while this
        // stack-owned dialog is alive, as in normal event-loop UI ownership.
        QEventLoop shown;
        QTimer::singleShot(50, &shown, &QEventLoop::quit);
        shown.exec();
        cancelled.reject();
    }
    if (live->ToJson() != liveBefore || !messages.isEmpty()) return fail("caller-editor-cancel");
    DialogEditProfile editor("", 41, &window);
    auto *name = editor.findChild<QLineEdit *>("name");
    if (!name) return fail("caller-editor-name");
    name->setText("synthetic-saved-edit");
    int accepted = 0;
    QObject::connect(&editor, &QDialog::accepted, [&] { ++accepted; });
    live->save_control_no_save = true;
    observer.reset();
    editor.accept();
    if (accepted || !messages.isEmpty() || observer.warnings != 1 || observer.questions || observer.unexpected ||
        live->ToJson() != liveBefore || live->last_save_content != profileCache ||
        !readFile(live->fn, bytes) || bytes != profileBytes) return fail("caller-editor-disabled");
    live->save_control_no_save = false;
    // Real Windows sharing denial at QSaveFile commit, rather than fake status.
#ifdef Q_OS_WIN
    const auto lockedPath = QFileInfo(live->fn).absoluteFilePath();
    const auto handle = CreateFileW(reinterpret_cast<LPCWSTR>(lockedPath.utf16()), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return fail("caller-editor-lock-open");
    observer.reset();
    editor.accept();
    const bool lockClosed = CloseHandle(handle);
    if (!lockClosed || accepted || !messages.isEmpty() || observer.warnings != 1 || observer.questions || observer.unexpected ||
        live->ToJson() != liveBefore || live->last_save_content != profileCache ||
        !readFile(live->fn, bytes) || bytes != profileBytes) return fail("caller-editor-write-failure");
#else
    return fail("caller-windows-required", 64);
#endif
    // Metadata is live, not the stale editor snapshot; preserve it on success.
    live->latency = 333;
    observer.reset();
    editor.accept();
    if (accepted != 1 || messages != QStringList{"accept,restart"} || observer.warnings || observer.questions || observer.unexpected ||
        live->bean->name != "synthetic-saved-edit" || live->latency != 333 ||
        !readFile(live->fn, bytes) || bytes != live->ToJsonBytes()) return fail("caller-editor-retry");
    messages.clear(); observer.reset();
    const auto unchangedJson = live->ToJson();
    const auto unchangedCache = live->last_save_content;
    const auto unchangedBytes = bytes;
    DialogEditProfile unchanged("", 41, &window);
    unchanged.accept();
    if (messages != QStringList{"accept"} || observer.warnings || observer.questions || observer.unexpected ||
        live->ToJson() != unchangedJson || live->last_save_content != unchangedCache ||
        !readFile(live->fn, bytes) || bytes != unchangedBytes) return fail("caller-editor-unchanged");
    messages.clear(); observer.reset();
    DialogEditProfile replaced("", 41, &window);
    const auto replacement = ProfileManager::NewProxyEntity(live->type);
    replacement->FromJson(live->ToJson()); replacement->fn = live->fn;
    profileManager->profiles[41] = replacement;
    replaced.accept();
    if (!messages.isEmpty() || observer.warnings != 1 || observer.questions || observer.unexpected ||
        replacement->ToJson() != unchangedJson || live->ToJson() != unchangedJson ||
        !readFile(live->fn, bytes) || bytes != unchangedBytes) return fail("caller-editor-replaced");
    profileManager->profiles[41] = live;
    messages.clear(); observer.reset();
    DialogEditProfile moved("", 41, &window);
    const auto path = live->fn;
    live->fn = "absent/moved-profile.json";
    moved.accept();
    if (!messages.isEmpty() || observer.warnings != 1 || observer.questions || observer.unexpected ||
        live->ToJson() != unchangedJson || live->last_save_content != unchangedCache || QFileInfo::exists("absent")) return fail("caller-editor-moved");
    live->fn = path;
    messages.clear(); observer.reset();
    DialogEditProfile stale("", 41, &window);
    live->bean->name = "synthetic-newer-edit";
    const auto newer = live->ToJson();
    stale.accept();
    if (!messages.isEmpty() || observer.warnings != 1 || observer.questions || observer.unexpected || live->ToJson() != newer ||
        !readFile(live->fn, bytes) || bytes != live->last_save_content) return fail("caller-editor-stale");
    dataStore->started_id = -1;
    // MainWindow writes only this known dashboard resource in isolated mode.
    QFile resource(":/neko/dashboard-notice.html");
    if (!resource.open(QIODevice::ReadOnly)) return fail("caller-dashboard-resource");
    if (!readFile("dashboard/index.html", bytes) || bytes != resource.readAll()) return fail("caller-dashboard-bytes");
    // QFile::copy from a read-only qrc resource can preserve its read-only bit.
    // Touch permissions only AFTER validating exact owned synthetic bytes.
    if (!QFile::setPermissions("dashboard/index.html", QFileDevice::ReadOwner | QFileDevice::WriteOwner) ||
        !QFile::remove("dashboard/index.html") || !QDir().rmdir("dashboard")) return fail("caller-dashboard-cleanup");
    Manifest after;
    if (!snapshot(args[2], "candidate", args[3], after)) return fail("caller-final-tree");
    before["groups/nekobox.json"] = after.value("groups/nekobox.json");
    before["profiles/41.json"] = after.value("profiles/41.json");
    if (after != before) return fail("caller-unrelated-mutated");
    QTextStream(stdout) << "LEGACY_MIGRATION_CALLERS_CHILD_PASS scope=settings-dispatch-existing-profile\n";
    return 0;
}

inline int run(QCoreApplication &app) {
    const auto args = app.arguments();
    if (args != QStringList{args.first(), "--legacy-migration-callers"}) return fail("caller-parent-arguments", 64);
    QTemporaryDir directory(QDir::tempPath() + "/mdmbox-legacy-migration-XXXXXX");
    directory.setAutoRemove(false);
    if (!directory.isValid() || !plainPath(directory.path(), true)) return fail("caller-workspace");
    const auto root = QFileInfo(directory.path()).canonicalFilePath();
    const auto token = QUuid::createUuid().toString(QUuid::Id128);
    if (!writeNew(root + '/' + OwnerFile, token.toUtf8())) return fail("caller-owner");
    for (const auto &role : {QString("seed"), QString("candidate")}) {
        const auto target = root + '/' + role;
        if (!QDir().mkdir(target) || !writeNew(target + '/' + RootFile, (token + ':' + role).toUtf8())) return fail("caller-root");
        for (const auto &dir : {QString("groups"), QString("profiles"), ROUTES_PREFIX_NAME}) if (!QDir(target).mkdir(dir)) return fail("caller-dir");
        const auto files = seedFiles();
        for (auto it = files.begin(); it != files.end(); ++it) if (!writeNew(target + '/' + it.key(), it.value())) return fail("caller-seed");
    }
    Manifest seed, candidate;
    if (!snapshot(root, "seed", token, seed) || !snapshot(root, "candidate", token, candidate)) return fail("caller-snapshot");
    const QStringList arguments{"--legacy-migration-callers-child", root, token, QString::fromLatin1(digest(candidate))};
    auto wrong = arguments; wrong[2] = QString(32, '0');
    if (!spawn(wrong, root + "/candidate", 64, "LEGACY_MIGRATION_FAIL caller-child-guard")) return fail("caller-negative");
    Manifest unmodified;
    if (!snapshot(root, "candidate", token, unmodified) || unmodified != candidate ||
        !spawn(arguments, root + "/candidate", 0, "LEGACY_MIGRATION_CALLERS_CHILD_PASS scope=settings-dispatch-existing-profile")) return fail("caller-execution");
    if (!snapshot(root, "seed", token, unmodified) || unmodified != seed || !cleanup(root, token) || QFileInfo::exists(root)) return fail("caller-cleanup");
    QTextStream(stdout) << "LEGACY_MIGRATION_CALLERS_PASS scope=settings-dispatch-existing-profile acceptance=NOT_ACCEPTED\n";
    return 0;
}
} // namespace LegacySaveCallerFixture
