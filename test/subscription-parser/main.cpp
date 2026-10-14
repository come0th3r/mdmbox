#include "sub/GroupUpdater.hpp"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>

class WorkingDirectoryGuard {
public:
    QString previous = QDir::currentPath();
    ~WorkingDirectoryGuard() { QDir::setCurrent(previous); }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
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
    QTextStream(stdout) << "SUBSCRIPTION_PARSER_STAGING_PASS checks=" << checks << "\n";
    return 0;
}
