#include "../../sub/ManagedProfile.hpp"
#include "../../sub/ManagedProfileStore.hpp"
#include "../../sub/MihomoValidator.hpp"
#include "../../sub/SubscriptionContract.hpp"
#include "../../sub/InstallationIdentity.hpp"
#include "../../sub/SubscriptionService.hpp"
#include <QUrlQuery>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QLockFile>
#include <QTemporaryDir>
#include <QTextStream>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QString contractError;
    NekoGui_sub::SubscriptionMetadata metadata;
    if (!NekoGui_sub::SubscriptionMetadata::parse({
            {"Subscription-Userinfo", "upload=4294967296; download=4294967297; total=8589934593; expire=2000000000"},
            {"Profile-Title", "base64:" + QStringLiteral("Синтетическая подписка").toUtf8().toBase64()},
            {"Profile-Update-Interval", "1"}, {"Support-Url", "https://example.invalid/help"}}, metadata, contractError) ||
        !metadata.exhausted() || metadata.expired(1999999999) || !metadata.expired(2000000000) ||
        metadata.title != QStringLiteral("Синтетическая подписка") || metadata.updateHours != 1) return 20;
    const auto title = metadata.title;
    for (const auto &bad : QList<QPair<QByteArray, QByteArray>>{
            {"Subscription-Userinfo", "total=-1"}, {"Subscription-Userinfo", "upload=18446744073709551616"},
            {"Subscription-Userinfo", "expire=9223372036854775808"}, {"Subscription-Userinfo", "total=1;total=2"},
            {"Profile-Title", "base64:%%%"}, {"Profile-Title", "base64:AA=="},
            {"Profile-Update-Interval", "0"}, {"Profile-Update-Interval", "169"},
            {"Support-Url", "javascript:alert(1)"}, {"Profile-Title", "line\r\ninjection"}}) {
        if (NekoGui_sub::SubscriptionMetadata::parse({bad}, metadata, contractError) ||
            metadata.title != title || contractError.isEmpty()) return 21;
    }
    if (NekoGui_sub::SubscriptionMetadata::parse({{"Profile-Title", "a"}, {"profile-title", "b"}}, metadata, contractError)) return 22;
    if (!NekoGui_sub::SubscriptionMetadata::parse({{"Subscription-Userinfo", "upload=18446744073709551615; download=18446744073709551615; total=0; expire=0"}}, metadata, contractError) ||
        metadata.exhausted() || metadata.expired(2000000000)) return 23;
    if (!NekoGui_sub::SubscriptionMetadata::parse({}, metadata, contractError) || metadata.total || metadata.updateHours) return 24;
    NekoGui_sub::ManagedSubscriptionRequest request;
    const QUrl url("https://example.invalid/custom/prefix/token?x=a%2Fb&x=c%2Bd&format=uri&format=yaml");
    if (!NekoGui_sub::ManagedSubscriptionRequest::build(url, "0.1.0", "1.19.32", request, contractError) ||
        request.url.path() != url.path() || QUrlQuery(request.url).allQueryItemValues("format") != QStringList{"clash"} ||
        QUrlQuery(request.url).allQueryItemValues("x") != QUrlQuery(url).allQueryItemValues("x") ||
        request.userAgent != "MDMBOX/0.1.0 mihomo/1.19.32") return 25;
    const auto goodUrl = request.url;
    if (NekoGui_sub::ManagedSubscriptionRequest::build(QUrl("http://example.invalid/token"), "0.1.0", "1.19.32", request, contractError) ||
        NekoGui_sub::ManagedSubscriptionRequest::build(url, "0.1.0", "fake\r\nheader", request, contractError) || request.url != goodUrl) return 26;
    QTextStream(stdout) << "SUBSCRIPTION_METADATA_REQUEST_PASS\n";
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
    const auto identityDirectory = QDir(directory.path()).filePath("identity");
    QString identity;
    if (!NekoGui_sub::InstallationIdentity::loadOrCreate(identityDirectory, identity, error) || identity.size() != 36) return 27;
    const auto firstIdentity = identity;
    if (!NekoGui_sub::InstallationIdentity::loadOrCreate(identityDirectory, identity, error) || identity != firstIdentity) return 28;
    const auto identityPath = QDir(identityDirectory).filePath("installation-identity.json");
    {
        QLockFile lock(identityPath + ".lock");
        if (!lock.tryLock() || NekoGui_sub::InstallationIdentity::loadOrCreate(identityDirectory, identity, error) ||
            identity != firstIdentity) return 29;
    }
    const auto copiedDirectory = QDir(directory.path()).filePath("copied-identity");
    if (!QDir().mkpath(copiedDirectory) || !QFile::copy(identityPath, QDir(copiedDirectory).filePath("installation-identity.json")) ||
        !NekoGui_sub::InstallationIdentity::loadOrCreate(copiedDirectory, identity, error) || identity != firstIdentity) return 30;
    {
        QFile damaged(identityPath);
        if (!damaged.open(QIODevice::WriteOnly | QIODevice::Truncate) || damaged.write("{}") != 2) return 31;
    }
    if (NekoGui_sub::InstallationIdentity::loadOrCreate(identityDirectory, identity, error) || identity != firstIdentity) return 32;
    QTextStream(stdout) << "INSTALLATION_IDENTITY_PASS\n";
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
    NekoGui_sub::SubscriptionMetadata serviceMetadata;
    serviceMetadata.title = "Synthetic service";
    serviceMetadata.upload = quint64(4294967296);
    serviceMetadata.total = quint64(0);
    serviceMetadata.updateHours = 1;
    const auto fetch = [&](const NekoGui_sub::ManagedSubscriptionRequest &r, const QString &hwid,
                           NekoGui_sub::SubscriptionDownload &d, QString &, const std::atomic_bool *) {
        if (hwid.size() != 36 || QUrlQuery(r.url).queryItemValue("format") != "clash") return false;
        d.source = source;
        d.metadata = serviceMetadata;
        return true;
    };
    const auto refresh = [&](const NekoGui_sub::ManagedProfileStore::Validator &v,
                             const std::atomic_bool *cancel = nullptr) {
        return NekoGui_sub::SubscriptionService::refresh(10, QUrl("https://example.invalid/token"), "0.1.0",
            copiedDirectory, store, fetch, v, error, cancel);
    };
    if (!refresh(accept)) return 33;
    const auto servicePath = QDir(directory.path()).filePath("10.json");
    const auto serviceBytes = readBytes(servicePath);
    NekoGui_sub::SubscriptionMetadata loadedMetadata;
    if (!store.loadMetadata(10, loadedMetadata, error) || loadedMetadata.title != serviceMetadata.title ||
        loadedMetadata.upload != serviceMetadata.upload || loadedMetadata.total != serviceMetadata.total) return 34;
    serviceMetadata.expiry = 1;
    if (refresh(accept) || readBytes(servicePath) != serviceBytes) return 35;
    serviceMetadata.expiry.reset();
    if (refresh(reject) || readBytes(servicePath) != serviceBytes) return 36;
    std::atomic_bool cancelled{false};
    const auto cancelDuringValidation = [&](const NekoGui_sub::ManagedProfile &, QString &) {
        cancelled = true;
        return true;
    };
    if (refresh(cancelDuringValidation, &cancelled) || readBytes(servicePath) != serviceBytes) return 37;
    {
        QLockFile lock(QDir(copiedDirectory).filePath("subscription-refresh-10.lock"));
        if (!lock.tryLock() || refresh(accept) || readBytes(servicePath) != serviceBytes) return 38;
    }
    QTextStream(stdout) << "SUBSCRIPTION_SERVICE_REFRESH_PASS\n";
    if (NekoGui_sub::MihomoValidator::verifyExecutable(path, error) ||
        NekoGui_sub::MihomoValidator::verifyExecutable("missing.exe", error)) return 39;
    if (app.arguments().size() == 2) {
        const auto exe = app.arguments().at(1);
        if (!NekoGui_sub::MihomoValidator::verifyExecutable(exe, error)) return 40;
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
