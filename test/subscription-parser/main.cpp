#ifdef _WIN32
#include <windows.h> // Before project enum names and Qt's interface macro.
#endif
#include "sub/GroupUpdater.hpp"
#include "db/ConfigBuilder.hpp"
#include "fmt/CustomBean.hpp"
#include "ExternalProcessFixture.hpp"
#include "CoreProcessFixture.hpp"
#include "LegacyMigrationFixture.hpp"
#include "LegacyMigrationAdversarial.hpp"
#include "LegacyBackupFixture.hpp"
#include "LegacyRestoreFixture.hpp"
#include "LegacySaveCallerFixture.hpp"
#include <QTimer>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTextStream>
#ifndef NKR_NO_YAML
#include "ManagedRefreshFixture.hpp"
int runManagedBridgeFixture(QApplication &app);
#endif

class WorkingDirectoryGuard {
public:
    QString previous = QDir::currentPath();
    ~WorkingDirectoryGuard() { QDir::setCurrent(previous); }
};

int main(int argc, char **argv) {
    // Keep the offline migration branch before QApplication and every other
    // fixture. Malformed migration arguments fail closed, never fall through.
    if (argc > 1 && QString::fromLocal8Bit(argv[1]).startsWith(QStringLiteral("--legacy-migration"))) {
        if (QString::fromLocal8Bit(argv[1]) == "--legacy-migration-callers-child") {
            QApplication app(argc, argv);
            return LegacySaveCallerFixture::child(app);
        }
        QCoreApplication app(argc, argv);
        if (app.arguments().value(1) == "--legacy-migration-callers") return LegacySaveCallerFixture::run(app);
        if (app.arguments().value(1) == "--legacy-migration-restore" ||
            app.arguments().value(1) == "--legacy-migration-restore-child" ||
            app.arguments().value(1) == "--legacy-migration-restore-interrupt-child") return LegacyRestoreFixture::run(app);
        if (app.arguments().value(1) == "--legacy-migration-backup" ||
            app.arguments().value(1) == "--legacy-migration-backup-verify-child") return LegacyBackupFixture::run(app);
        if (app.arguments().value(1) == "--legacy-migration-adversarial" ||
            app.arguments().value(1) == "--legacy-migration-edge-child") return LegacyMigrationAdversarial::run(app);
        return LegacyMigrationFixture::run(app);
    }
    if (argc == 2 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--daemon-event-child")) {
        QCoreApplication child(argc, argv);
        QTextStream(stdout) << "grpc server listening\n" << Qt::flush;
        QTimer::singleShot(100, &child, [] { QCoreApplication::exit(42); });
        return child.exec();
    }
    if (argc == 2 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--external-process-child")) {
        QCoreApplication child(argc, argv);
        QTimer::singleShot(10000, &child, &QCoreApplication::quit);
        return child.exec();
    }
    QCoreApplication::setAttribute(Qt::AA_ShareOpenGLContexts);
    QApplication app(argc, argv);
#ifndef NKR_NO_YAML
    if (app.arguments().contains(QStringLiteral("--managed-bridge-e2e"))) return runManagedBridgeFixture(app);
#endif
    // Production window installs these callbacks; isolated runner must supply safe sinks.
    MW_show_log = [](QString) {};
    MW_dialog_message = [](QString, QString) {};
    if (!runExternalProcessFixture()) return 80;
    if (!runCoreProcessFixture()) return 81;
    QTemporaryDir directory;
    WorkingDirectoryGuard workingDirectory; // Restore cwd before temporary directory cleanup.
    if (!directory.isValid() || !QDir::setCurrent(directory.path())) return 2;
    QDir().mkpath("profiles");
    QDir().mkpath("groups");
    auto group = NekoGui::ProfileManager::NewGroup();
    group->name = "synthetic";
    NekoGui::profileManager->AddGroup(group);
    const QString link = "socks5://127.0.0.1:12345#synthetic";
    NekoGui_sub::RawUpdater initial;
    initial.gid_add_to = group->id;
    initial.update(link);
    if (group->Profiles().size() != 1) return 3;
    const auto original = group->Profiles().first();
    const auto originalFiles = QDir("profiles").entryList(QDir::Files);
    QFile stored(original->fn);
    if (!stored.open(QIODevice::ReadOnly)) return 9;
    const auto originalBytes = stored.readAll();
    stored.close();
    auto unchanged = [&] {
        QFile current(original->fn);
        return group->Profiles().size() == 1 && group->Profiles().first() == original &&
               QDir("profiles").entryList(QDir::Files) == originalFiles &&
               current.open(QIODevice::ReadOnly) && current.readAll() == originalBytes;
    };
    int checks = 0;
    auto check = [&](bool ok) {
        ++checks;
        if (!ok) QTextStream(stderr) << "FAILED check " << checks << "\n";
        return ok;
    };
    for (const auto &payload : QStringList{
             link, QString::fromLatin1(link.toUtf8().toBase64()),
             "{\"type\":\"socks\",\"server\":\"127.0.0.1\",\"server_port\":12346}",
             "proxies:\n  - {name: synthetic, type: socks5, server: 127.0.0.1, port: 12347}\n"}) {
        NekoGui_sub::RawUpdater parser;
        parser.stage_only = true;
        parser.gid_add_to = group->id;
        parser.update(payload);
        if (!check(!parser.parse_failed && parser.updated_order.size() == 1)) return 4;
        if (!check(parser.updated_order.first()->id < 0)) return 5;
        if (!check(unchanged())) return 6;
    }
    for (const auto &payload : QStringList{"", "<!doctype html><html>error</html>",
                                          "proxies: [", "{broken", "not a subscription"}) {
        NekoGui_sub::RawUpdater parser;
        parser.stage_only = true;
        parser.update(payload);
        if (!check(parser.parse_failed || parser.updated_order.isEmpty())) return 7;
        if (!check(unchanged())) return 8;
    }
    group->url = "https://example.invalid/synthetic";
    group->info = "synthetic metadata";
    group->sub_last_update = 123456789;
    group->order = {original->id};
    group->subscription_kind = "mihomo-full";
    group->Save(); // Save returns changed, not write success; verify by reading the file.
    auto readBytes = [](const QString &path) {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{};
    };
    const auto savedGroup = readBytes(group->fn);
    const auto savedObject = QJsonDocument::fromJson(savedGroup).object();
    if (!check(!savedGroup.isEmpty() && savedObject.value("subscription_kind").toString() == "mihomo-full")) return 10;
    NekoGui::Group loaded;
    loaded.fn = group->fn;
    if (!check(loaded.Load() && loaded.ToJson() == group->ToJson())) return 11;
    auto legacyObject = savedObject;
    legacyObject.remove("subscription_kind");
    NekoGui::Group legacy;
    legacy.FromJson(legacyObject);
    if (!check(legacy.subscription_kind == "links" && legacy.order == group->order &&
               legacy.url == group->url && legacy.info == group->info &&
               legacy.sub_last_update == group->sub_last_update)) return 12;
    NekoGui_sub::GroupUpdater updater;
    // Unknown kinds must return before network or legacy import/deletion.
    group->subscription_kind = "future-unsupported";
    group->Save();
    const auto unsupportedGroup = readBytes(group->fn);
    updater.Update(link, group->id, false);
    if (!check(unchanged() && readBytes(group->fn) == unsupportedGroup &&
               !QFile::exists("managed-subscriptions/" + QString::number(group->id) + ".json"))) return 13;
    group->subscription_kind = "mihomo-full";
    group->Save();
    const auto managedGroup = readBytes(group->fn);
    // No pinned core => preflight rejection; if present, HTTP is rejected before fetch.
    updater.Update("http://127.0.0.1:1/synthetic", group->id, false);
    if (!check(unchanged() && readBytes(group->fn) == managedGroup &&
               group->info == "synthetic metadata" && group->sub_last_update == 123456789 &&
               !QFile::exists("managed-subscriptions/" + QString::number(group->id) + ".json"))) return 14;
    QTextStream(stdout) << "GROUP_MODE_PERSISTENCE_AND_FAILURE_PRESERVATION_PASS\n";
    // All modes must refuse stale legacy entries before generating any config.
    for (const auto &kind : QStringList{"mihomo-full", "future-unsupported"}) {
        group->subscription_kind = kind;
        for (int mode = 0; mode < 3; ++mode) {
            const auto result = NekoGui::BuildConfig(original, mode == 1, mode == 2);
            if (!check(!result->error.isEmpty() && result->coreConfig.isEmpty() &&
                       result->outboundStats.isEmpty() && result->extRs.empty())) return 16;
        }
        auto *bean = new NekoGui_fmt::CustomBean;
        bean->core = "internal-full";
        bean->config_simple = "{\"synthetic\":true}";
        auto custom = std::make_shared<NekoGui::ProxyEntity>(bean, "custom");
        custom->gid = group->id;
        if (!check(NekoGui::BuildConfig(custom, false, false)->coreConfig.isEmpty())) return 17;
        auto status = std::make_shared<NekoGui::BuildConfigStatus>();
        status->result = std::make_shared<NekoGui::BuildConfigResult>();
        // Chain members/front/global outbounds share this generation boundary.
        if (!check(NekoGui::BuildChainInternal(0, {original}, status).isEmpty() &&
                   !status->result->error.isEmpty() && status->result->extRs.empty())) return 18;
    }
    group->subscription_kind = "links";
    auto *bean = new NekoGui_fmt::CustomBean;
    bean->core = "internal-full";
    bean->config_simple = "{\"synthetic\":true}";
    auto custom = std::make_shared<NekoGui::ProxyEntity>(bean, "custom");
    custom->gid = group->id;
    const auto legacyConfig = NekoGui::BuildConfig(custom, false, false);
    if (!check(legacyConfig->error.isEmpty() && legacyConfig->coreConfig.value("synthetic").toBool())) return 19;
    group->subscription_kind = "mihomo-full";
    if (!check(unchanged() && readBytes(group->fn) == managedGroup)) return 20;
    QTextStream(stdout) << "LEGACY_MANAGED_FALLBACK_REFUSAL_PASS\n";
#ifndef NKR_NO_YAML
    if (app.arguments().size() == 3) {
        if (!testManagedHttpsRefresh(app.arguments()[1], app.arguments()[2], group, unchanged)) return 15;
        QTextStream(stdout) << "PRODUCTION_GROUP_HTTPS_REAL_CORE_REFRESH_PASS\n";
    }
#endif
    QTextStream(stdout) << "SUBSCRIPTION_PARSER_STAGING_PASS checks=" << checks << "\n";
    return 0;
}
