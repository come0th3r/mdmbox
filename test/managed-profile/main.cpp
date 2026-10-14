#include "../../sub/ManagedProfile.hpp"
#include "../../sub/ManagedProfileStore.hpp"
#include "../../sub/MihomoValidator.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QLockFile>
#include <QTemporaryDir>
#include <QTextStream>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const QByteArray source =
        "# synthetic, no private config\n"
        "proxies:\n  - {name: node, type: socks5, server: 127.0.0.1, port: 12345, future-field: keep}\n"
        "proxy-groups:\n  - {name: select, type: select, proxies: [node, DIRECT]}\n"
        "rules: ['DOMAIN,example.invalid,select', 'MATCH,select']\n"
        "dns: {enable: true, nameserver: [127.0.0.1]}\n"
        "rule-providers: {synthetic: {type: file, path: rules/synthetic.yaml}}\n";
    NekoGui_sub::ManagedProfile profile;
    QString error;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(source, profile, error)) return 1;
    if (profile.source != source || profile.sha256.size() != 64 ||
        profile.rules != QStringList{"DOMAIN,example.invalid,select", "MATCH,select"} ||
        profile.proxyNames != QStringList{"node"}) return 2;
    const auto hash = profile.sha256;
    QByteArray duplicate = source;
    duplicate.replace("name: select", "name: node");
    QByteArray malformedRules = source;
    malformedRules.replace("'MATCH,select'", "{}");
    QByteArray malformedProvider = source;
    malformedProvider.replace("{synthetic: {type: file, path: rules/synthetic.yaml}}", "[]");
    int rejected = 0;
    for (const auto &invalid : QList<QByteArray>{
             {}, "<html>error</html>", "proxies: [", source + "---\na: b\n",
             source + "dns: {}\n", source + "nested: {key: 1, key: 2}\n",
             source + "cycle: &cycle [*cycle]\n", QByteArray(4 * 1024 * 1024 + 1, 'a'),
             source + QByteArray(1, '\0'), source + QByteArray(1, char(0xff)),
             "proxies: []\nproxy-groups: []\nrules: []\ndns: {}\n",
             duplicate, malformedRules, malformedProvider}) {
        if (NekoGui_sub::ManagedProfile::ParseMihomo(invalid, profile, error) || error.isEmpty() ||
            profile.source != source || profile.sha256 != hash) return 3;
        ++rejected;
    }
    QTextStream(stdout) << "MANAGED_PROFILE_STRUCTURE_PASS rejected=" << rejected << "\n";
    QTemporaryDir directory;
    if (!directory.isValid()) return 4;
    NekoGui_sub::ManagedProfileStore store(directory.path());
    const auto accept = [](const NekoGui_sub::ManagedProfile &, QString &) { return true; };
    const auto reject = [](const NekoGui_sub::ManagedProfile &, QString &e) { e = "private details"; return false; };
    auto readBytes = [](const QString &path) {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{};
    };
    const auto path = QDir(directory.path()).filePath("7.json");
    if (!store.commit(7, source, accept, error) || !store.load(7, profile, error) || profile.source != source) return 5;
    const auto original = readBytes(path);
    if (store.commit(7, source, reject, error) || error.contains("private") || readBytes(path) != original) return 6;
    if (store.commit(7, {}, accept, error) || store.commit(7, source, {}, error) ||
        store.commit(-1, source, accept, error) || readBytes(path) != original) return 7;
    {
        QLockFile lock(path + ".lock");
        if (!lock.tryLock() || store.commit(7, source, accept, error) || readBytes(path) != original) return 8;
    }
    const auto updated = source + "# refreshed\n";
    if (!store.commit(7, updated, accept, error) || readBytes(path + ".previous") != original ||
        !store.load(7, profile, error) || profile.source != updated) return 9;
    {
        QFile corrupt(path);
        if (!corrupt.open(QIODevice::WriteOnly | QIODevice::Truncate) || corrupt.write("{}") != 2) return 10;
    }
    if (store.load(7, profile, error) || profile.source != updated ||
        store.commit(7, source, accept, error) || readBytes(path) != "{}") return 11;
    const auto otherPath = QDir(directory.path()).filePath("8.json");
    if (!store.commit(8, source, accept, error)) return 12;
    const auto otherOriginal = readBytes(otherPath);
    // Deterministic snapshot-write failure must not replace the current document.
    if (!QDir().mkdir(otherPath + ".previous") || store.commit(8, updated, accept, error) ||
        readBytes(otherPath) != otherOriginal) return 13;
    QTextStream(stdout) << "MANAGED_PROFILE_STORE_PASS\n";
    if (app.arguments().size() == 2) {
        const auto exe = app.arguments().at(1);
        QByteArray valid = source;
        valid.replace("rule-providers: {synthetic: {type: file, path: rules/synthetic.yaml}}\n", "");
        NekoGui_sub::ManagedProfile candidate;
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(valid, candidate, error) ||
            !NekoGui_sub::MihomoValidator::validate(exe, candidate, error)) {
            QTextStream(stderr) << error << "\n";
            return 14;
        }
        auto invalid = valid;
        invalid.replace("type: socks5", "type: deliberately-unsupported");
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(invalid, candidate, error) ||
            NekoGui_sub::MihomoValidator::validate(exe, candidate, error)) return 15;
        const auto coreValidate = [&](const NekoGui_sub::ManagedProfile &p, QString &e) {
            return NekoGui_sub::MihomoValidator::validate(exe, p, e);
        };
        if (!store.commit(9, valid, coreValidate, error)) return 16;
        const auto runtimePath = QDir(directory.path()).filePath("9.json");
        const auto runtimeBytes = readBytes(runtimePath);
        if (store.commit(9, invalid, coreValidate, error) || readBytes(runtimePath) != runtimeBytes ||
            NekoGui_sub::MihomoValidator::validate(path, candidate, error) ||
            NekoGui_sub::MihomoValidator::validate("missing.exe", candidate, error)) return 17;
        QTextStream(stdout) << "PINNED_MIHOMO_VALIDATOR_PASS\n";
    }
    return 0;
}
