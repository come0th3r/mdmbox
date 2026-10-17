#include "../../sub/ManagedProfile.hpp"
#include "../../sub/ManagedProfileStore.hpp"
#include "../../sub/MihomoValidator.hpp"
#include "../../sub/SubscriptionContract.hpp"
#include "../../sub/InstallationIdentity.hpp"
#include "../../sub/SubscriptionService.hpp"
#include "../../sub/ManagedRuntimePolicy.hpp"
#include <QUrlQuery>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSemaphore>
#include <QTemporaryDir>
#include <QTextStream>
#include <chrono>
#include <thread>
#include <yaml-cpp/yaml.h>

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

    const QByteArray fullProfile =
        "# full synthetic panel document\n"
        "mixed-port: 17890\nmode: rule\n\n"
        "proxies:\n"
        "  - {name: node-a, type: socks5, server: 127.0.0.1, port: 12345, future-field: keep}\n"
        "  - {name: node-b, type: http, server: 127.0.0.1, port: 12346}\n"
        "proxy-groups:\n"
        "  - {name: select, type: select, proxies: [node-a, node-b, DIRECT]}\n"
        "  - {name: fallback, type: fallback, proxies: [select, node-b], url: 'https://example.invalid/check', interval: 300}\n"
        "rules:\n"
        "  - 'DOMAIN,first.example,select'\n"
        "  - 'IP-CIDR,192.0.2.0/24,fallback,no-resolve'\n"
        "  - 'MATCH,select'\n"
        "rule-providers:\n"
        "  synthetic-domain: {type: http, behavior: domain, url: 'https://example.invalid/domain.yaml', path: ./rules/domain.yaml, interval: 3600}\n"
        "  synthetic-ip: {type: file, behavior: ipcidr, path: ./rules/ip.yaml, format: yaml}\n"
        "dns:\n"
        "  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n"
        "  nameserver: [127.0.0.1, 'https://dns.example.invalid/dns-query']\n"
        "  fallback: ['tls://dns.example.invalid']\n"
        "  nameserver-policy: {'domain:example.invalid': [127.0.0.1]}\n"
        "  fake-ip-filter: ['*.example.invalid', 'localhost']\n"
        "hosts: {synthetic.example.invalid: 192.0.2.10}\n"
        "profile: {store-selected: true, store-fake-ip: false}\n"
        "unified-delay: true\n";
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
    auto selfContained = source;
    selfContained.replace("rule-providers: {synthetic: {type: file, path: rules/synthetic.yaml}}\n", "");
    selfContained.replace(", future-field: keep", "");
    NekoGui_sub::ManagedProfile runtimeCandidate;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(selfContained, runtimeCandidate, error) ||
        !NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(runtimeCandidate, error)) return 51;
    for (const auto &addition : QList<QByteArray>{
             "rule-providers: {}\n", "proxy-providers: {}\n", "geox-url: {}\n",
             "tun: {enable: false}\n", "listeners: []\n", "tunnels: []\n",
             "external-controller: 0.0.0.0:9090\n", "external-controller-pipe: synthetic\n",
             "external-ui-url: https://example.invalid/ui.zip\n", "secret: synthetic-not-a-real-secret\n",
             "interface-name: synthetic\n", "authentication: []\n"}) {
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(selfContained + addition, runtimeCandidate, error) ||
            NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(runtimeCandidate, error) || error.isEmpty()) return 52;
    }
    for (const auto &rule : {"GEOIP,LAN,DIRECT", "GEOSITE,category-ru,DIRECT", "RULE-SET,synthetic,DIRECT",
                             "AND,((NETWORK,UDP),(GEOIP,ru)),DIRECT"}) {
        auto dependent = selfContained;
        dependent.replace("MATCH,select", rule);
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(dependent, runtimeCandidate, error) ||
            NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(runtimeCandidate, error)) return 53;
    }
    auto dnsDependent = selfContained;
    dnsDependent.replace("nameserver: [127.0.0.1]", "nameserver-policy: {'geosite:category-ru': [127.0.0.1]}");
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(dnsDependent, runtimeCandidate, error) ||
        NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(runtimeCandidate, error) || profile.source != source) return 54;
    QTextStream(stdout) << "MANAGED_RUNTIME_RESOURCE_GATE_PASS\n";
    NekoGui_sub::ManagedProfile projected;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(selfContained +
            "mixed-port: 9999\nport: 8888\nallow-lan: true\nbind-address: '*'\nmode: global\n", runtimeCandidate, error) ||
        !NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346,
            QByteArray(64, 'a'), projected, error)) return 55;
    const auto projectedRoot = YAML::Load(projected.source.toStdString());
    if (projectedRoot["mixed-port"].as<int>() != 12345 || projectedRoot["port"].as<int>() != 0 ||
        projectedRoot["allow-lan"].as<bool>() || projectedRoot["tun"]["enable"].as<bool>() ||
        projectedRoot["bind-address"].as<std::string>() != "127.0.0.1" ||
        projectedRoot["external-controller"].as<std::string>() != "127.0.0.1:12346" ||
        projectedRoot["mode"].as<std::string>() != "rule" || projectedRoot["dns"]["listen"].IsDefined() ||
        projectedRoot["dns"]["use-system-hosts"].as<bool>() ||
        projected.rules != runtimeCandidate.rules || projected.proxyNames != runtimeCandidate.proxyNames ||
        runtimeCandidate.source.contains("external-controller")) return 56;
    const auto projectedBytes = projected.source;
    const auto panelSourceBeforeOverrides = runtimeCandidate.source;
    const auto panelRulesBeforeOverrides = runtimeCandidate.rules;
    NekoGui_sub::ManagedRuntimeRuleOverrides overrides;
    overrides.technicalRules = {"IP-CIDR,127.0.0.1/32,DIRECT,no-resolve"};
    overrides.localRules = {"DOMAIN-SUFFIX,local.example,select"};
    NekoGui_sub::ManagedProfile overrideProjection;
    if (!NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346,
            QByteArray(64, 'a'), overrides, overrideProjection, error)) return 111;
    const QStringList expectedOverrideRules{
        "IP-CIDR,127.0.0.1/32,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,local.example,select",
        "DOMAIN,example.invalid,select", "MATCH,select"};
    const auto overrideRoot = YAML::Load(overrideProjection.source.toStdString());
    if (overrideProjection.rules != expectedOverrideRules ||
        runtimeCandidate.source != panelSourceBeforeOverrides ||
        runtimeCandidate.rules != panelRulesBeforeOverrides ||
        overrideRoot["rules"].size() != size_t(expectedOverrideRules.size())) return 112;
    const auto overrideBytes = overrideProjection.source;
    overrides.localRules = {"   "};
    if (NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346,
            QByteArray(64, 'a'), overrides, overrideProjection, error) || error.isEmpty() ||
        overrideProjection.source != overrideBytes || runtimeCandidate.source != panelSourceBeforeOverrides) return 113;
    QTextStream(stdout) << "MANAGED_RULE_LAYER_PRIORITY_AND_PANEL_IMMUTABILITY_PASS\n";
    if (NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 80, 12346, QByteArray(64, 'a'), projected, error) ||
        NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12345, QByteArray(64, 'a'), projected, error) ||
        NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346, "bad", projected, error) ||
        projected.source != projectedBytes) return 57;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(selfContained + "future-control: true\n", runtimeCandidate, error) ||
        NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346, QByteArray(64, 'a'), projected, error) ||
        projected.source != projectedBytes) return 58;
    QTextStream(stdout) << "MANAGED_LOOPBACK_PROJECTION_PASS\n";
    for (const auto &replacement : QList<QPair<QByteArray, QByteArray>>{
             {"type: socks5", "type: socks5, dialer-proxy: node"},
             {"type: socks5", "type: socks5, interface-name: synthetic"},
             {"type: socks5", "type: socks5, future-field: keep"},
             {"type: select", "type: url-test, url: https://example.invalid/check"},
             {"proxies: [node, DIRECT]", "proxies: [select]"},
             {"nameserver: [127.0.0.1]", "nameserver: ['https://example.invalid/dns-query']"},
             {"nameserver: [127.0.0.1]", "nameserver: [127.0.0.1], proxy-server-nameserver: [127.0.0.1]"}}) {
        auto nested = selfContained;
        nested.replace(replacement.first, replacement.second);
        if (nested == selfContained || !NekoGui_sub::ManagedProfile::ParseMihomo(nested, runtimeCandidate, error) ||
            NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346,
                QByteArray(64, 'a'), projected, error) || projected.source != projectedBytes) return 60;
    }
    QTextStream(stdout) << "MANAGED_NESTED_RUNTIME_GATE_PASS\n";
    auto httpProxyProfile = selfContained;
    httpProxyProfile.replace("type: socks5", "type: http");
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(httpProxyProfile, runtimeCandidate, error) ||
        !NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(runtimeCandidate, error) ||
        !NekoGui_sub::ManagedRuntimePolicy::projectLoopback(runtimeCandidate, 12345, 12346,
            QByteArray(64, 'a'), projected, error)) return 114;
    const auto httpProxyRoot = YAML::Load(projected.source.toStdString());
    if (httpProxyRoot["proxies"][0]["type"].as<std::string>() != "http" ||
        projected.proxyNames != runtimeCandidate.proxyNames) return 115;
    QTextStream(stdout) << "MANAGED_HTTP_PROXY_PROJECTION_PASS\n";
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
    NekoGui_sub::ManagedProfile fullParsed;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(fullProfile, fullParsed, error) ||
        fullParsed.source != fullProfile || fullParsed.rules != QStringList{
            "DOMAIN,first.example,select", "IP-CIDR,192.0.2.0/24,fallback,no-resolve", "MATCH,select"} ||
        !store.commit(70, fullProfile, accept, error) || !store.load(70, fullParsed, error) ||
        fullParsed.source != fullProfile || fullParsed.sha256 != QCryptographicHash::hash(fullProfile, QCryptographicHash::Sha256).toHex()) return 52;
    const auto fullYaml = YAML::Load(fullParsed.source.toStdString());
    const auto storedRules = fullYaml["rules"];
    const auto storedGroups = fullYaml["proxy-groups"];
    const auto storedProviders = fullYaml["rule-providers"];
    const auto storedDns = fullYaml["dns"];
    if (!storedRules.IsSequence() || storedRules.size() != 3 ||
        storedRules[0].as<std::string>() != "DOMAIN,first.example,select" ||
        storedRules[1].as<std::string>() != "IP-CIDR,192.0.2.0/24,fallback,no-resolve" ||
        storedRules[2].as<std::string>() != "MATCH,select" ||
        !storedGroups.IsSequence() || storedGroups.size() != 2 ||
        storedGroups[0]["proxies"].size() != 3 || storedGroups[1]["type"].as<std::string>() != "fallback" ||
        storedProviders.size() != 2 || storedProviders["synthetic-domain"]["interval"].as<int>() != 3600 ||
        !storedDns["enable"].as<bool>() || storedDns["enhanced-mode"].as<std::string>() != "fake-ip" ||
        storedDns["nameserver-policy"]["domain:example.invalid"][0].as<std::string>() != "127.0.0.1" ||
        fullYaml["hosts"]["synthetic.example.invalid"].as<std::string>() != "192.0.2.10" ||
        !fullYaml["profile"]["store-selected"].as<bool>() || !fullYaml["unified-delay"].as<bool>()) return 53;
    QTextStream(stdout) << "MANAGED_FULL_PROFILE_ORDERED_ROUNDTRIP_PASS\n";
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
    const QStringList notices{
        QStringLiteral("⛔ Все места для устройств заняты — откройте ссылку подписки в браузере"),
        QStringLiteral("⛔ All device places are taken — open the subscription link in a browser"),
        QStringLiteral("⛔ Для этого приложения нет подходящих серверов — откройте ссылку подписки в браузере"),
        QStringLiteral("⛔ There are no servers this app can use — open the subscription link in a browser"),
        QStringLiteral("⛔ Устройство заблокировано"), QStringLiteral("⛔ This device is blocked"),
        QStringLiteral("⛔ Приложение не сообщает ID устройства — поставьте Happ, Koala Clash или INCY"),
        QStringLiteral("⛔ The app does not send a device ID — install Happ, Koala Clash or INCY"),
        QStringLiteral("⏸ Устройство отвязано — подключится снова через 2 ч"),
        QStringLiteral("⏸ This device was unbound — it can connect again in 2 h"),
        QStringLiteral("⏸ Устройство отвязано — подключить его снова может только администратор"),
        QStringLiteral("⏸ This device was unbound — only the administrator can let it connect again")};
    if (!store.commit(11, source, accept, error)) return 47;
    const auto noticePath = QDir(directory.path()).filePath("11.json");
    const auto beforeNotice = readBytes(noticePath);
    for (const auto &notice : notices) {
        const auto stub = QStringLiteral("proxies: [{name: '%1', type: socks5, server: 127.0.0.1, port: 1}]\n"
            "proxy-groups: [{name: custom-main, type: select, proxies: ['%1']}]\n"
            "rules: ['MATCH,custom-main']\n").arg(notice).toUtf8();
        if (NekoGui_sub::ManagedProfile::ParseMihomo(stub, profile, error) ||
            !error.contains("notice") || store.commit(11, stub, accept, error) ||
            readBytes(noticePath) != beforeNotice) return 48;
        // Adding DNS must not make the notice acceptable; normal local proxies remain valid.
        if (NekoGui_sub::ManagedProfile::ParseMihomo(stub + "dns: {}\n", profile, error)) return 49;
        auto ordinary = stub + "dns: {}\n";
        ordinary.replace(notice.toUtf8(), "local-test");
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(ordinary, profile, error)) return 50;
    }
    QTextStream(stdout) << "MIKAN_DENIAL_NOTICE_PASS cases=" << notices.size() << "\n";
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
    NekoGui_sub::SubscriptionService::CommittedSnapshot committed;
    const auto refresh = [&](const NekoGui_sub::ManagedProfileStore::Validator &v,
                             const std::atomic_bool *cancel = nullptr) {
        return NekoGui_sub::SubscriptionService::refresh(10, QUrl("https://example.invalid/token"), "0.1.0",
            copiedDirectory, store, fetch, v, error, cancel, &committed);
    };
    if (!refresh(accept)) return 33;
    if (committed.profile.source != source || committed.profile.sha256.isEmpty() ||
        committed.metadata.title != serviceMetadata.title || committed.metadata.upload != serviceMetadata.upload) return 101;
    // Deterministic interleaving: a later writer changes source AND metadata.
    // The caller's committed candidate must remain the exact earlier version.
    auto newerMetadata = serviceMetadata;
    newerMetadata.title = "Later writer";
    if (!store.commit(10, updated, newerMetadata, accept, error) ||
        committed.profile.source != source || committed.metadata.title != serviceMetadata.title ||
        !store.loadSnapshot(10, profile, newerMetadata, error) || profile.source != updated ||
        newerMetadata.title != "Later writer") return 102;
    if (!refresh(accept)) return 103;
    const auto servicePath = QDir(directory.path()).filePath("10.json");
    const auto serviceBytes = readBytes(servicePath);
    NekoGui_sub::SubscriptionMetadata loadedMetadata;
    if (!store.loadMetadata(10, loadedMetadata, error) || loadedMetadata.title != serviceMetadata.title ||
        loadedMetadata.upload != serviceMetadata.upload || loadedMetadata.total != serviceMetadata.total) return 34;
    serviceMetadata.expiry = 1;
    if (refresh(accept) || readBytes(servicePath) != serviceBytes) return 35;
    serviceMetadata.expiry.reset();
    if (refresh(reject) || readBytes(servicePath) != serviceBytes) return 36;
    const QByteArray providerCandidate =
        "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 12345}]\n"
        "proxy-groups: [{name: select, type: select, proxies: [node, DIRECT]}]\n"
        "rules: ['RULE-SET,synthetic,DIRECT', 'MATCH,select']\n"
        "rule-providers:\n"
        "  synthetic: {type: file, behavior: domain, path: ./rules/synthetic.yaml, format: yaml}\n"
        "dns: {enable: true, nameserver: [127.0.0.1]}\n";
    NekoGui_sub::ManagedProfile parsedProvider;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(providerCandidate, parsedProvider, error) ||
        !parsedProvider.source.contains("RULE-SET,synthetic,DIRECT") ||
        !parsedProvider.source.contains("rule-providers:")) return 109;
    const auto providerFetcher = [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
                                     NekoGui_sub::SubscriptionDownload &download, QString &, const std::atomic_bool *) {
        download.source = providerCandidate;
        download.metadata = serviceMetadata;
        return true;
    };
    NekoGui_sub::SubscriptionService::CommittedSnapshot providerOutput;
    providerOutput.profile.source = QByteArray("provider-output-sentinel");
    providerOutput.metadata.title = QStringLiteral("provider-output-sentinel");
    bool providerValidatorCalled = false;
    const NekoGui_sub::ManagedProfileStore::Validator providerValidator =
        [&](const NekoGui_sub::ManagedProfile &candidate, QString &validationError) {
            providerValidatorCalled = true;
            return NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(candidate, validationError);
        };
    if (NekoGui_sub::SubscriptionService::refresh(10, QUrl("https://example.invalid/provider-fixture"),
            "0.1.0", copiedDirectory, store, providerFetcher, providerValidator, error, nullptr, &providerOutput) ||
        !providerValidatorCalled || error.isEmpty() || readBytes(servicePath) != serviceBytes ||
        providerOutput.profile.source != QByteArray("provider-output-sentinel") ||
        providerOutput.metadata.title != QStringLiteral("provider-output-sentinel")) return 110;
    QTextStream(stdout) << "SUBSCRIPTION_PROVIDER_RESOURCE_REJECTION_PRESERVES_LAST_KNOWN_GOOD_PASS\n";
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
    // Deterministic overlapping service calls: hold the first request inside
    // its fetcher, then submit a second refresh for the same group. It must be
    // refused before its fetcher runs, while the first exact commit succeeds.
    if (!store.commit(12, source, serviceMetadata, accept, error)) return 105;
    QSemaphore fetchEntered, releaseFetch;
    const auto concurrentCandidate = source + "# concurrent refresh winner\n";
    auto concurrentMetadata = serviceMetadata;
    concurrentMetadata.title = "Concurrent winner";
    NekoGui_sub::SubscriptionService::CommittedSnapshot concurrentCommitted;
    QString concurrentError;
    bool concurrentSuccess = false;
    int firstFetcherCalls = 0;
    const NekoGui_sub::SubscriptionService::Fetcher blockingFetch =
        [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
            NekoGui_sub::SubscriptionDownload &download, QString &fetchError, const std::atomic_bool *) {
            ++firstFetcherCalls;
            fetchEntered.release();
            if (!releaseFetch.tryAcquire(1, 10000)) {
                fetchError = QStringLiteral("Concurrent fixture release timed out");
                return false;
            }
            download.source = concurrentCandidate;
            download.metadata = concurrentMetadata;
            return true;
        };
    std::thread refreshThread([&] {
        concurrentSuccess = NekoGui_sub::SubscriptionService::refresh(12,
            QUrl("https://example.invalid/concurrent"), "0.1.0", copiedDirectory, store,
            blockingFetch, accept, concurrentError, nullptr, &concurrentCommitted);
    });
    const bool enteredFetch = fetchEntered.tryAcquire(1, 5000);
    int competingFetcherCalls = 0;
    QString competingRefreshError;
    NekoGui_sub::SubscriptionService::CommittedSnapshot competingCommitted;
    const NekoGui_sub::SubscriptionService::Fetcher competingFetch =
        [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
            NekoGui_sub::SubscriptionDownload &, QString &, const std::atomic_bool *) {
            ++competingFetcherCalls;
            return false;
        };
    const bool competingSuccess = NekoGui_sub::SubscriptionService::refresh(12,
        QUrl("https://example.invalid/concurrent"), "0.1.0", copiedDirectory, store,
        competingFetch, accept, competingRefreshError, nullptr, &competingCommitted);
    releaseFetch.release();
    refreshThread.join();
    NekoGui_sub::ManagedProfile concurrentStored;
    NekoGui_sub::SubscriptionMetadata concurrentStoredMetadata;
    if (!enteredFetch || competingSuccess || competingFetcherCalls != 0 ||
        competingRefreshError.isEmpty() || !concurrentSuccess || firstFetcherCalls != 1 ||
        concurrentCommitted.profile.source != concurrentCandidate ||
        concurrentCommitted.metadata.title != concurrentMetadata.title ||
        !store.loadSnapshot(12, concurrentStored, concurrentStoredMetadata, error) ||
        concurrentStored.source != concurrentCandidate ||
        concurrentStoredMetadata.title != concurrentMetadata.title) return 106;
    QTextStream(stdout) << "SUBSCRIPTION_CONCURRENT_REFRESH_SERIALIZED_EXACT_COMMIT_PASS\n";
    // Expiry can cross while the core validator is running. The service must
    // recheck the fetched policy after validation and before the store commit,
    // preserving the prior last-known-good envelope and caller output.
    auto expiringMetadata = serviceMetadata;
    expiringMetadata.expiry = QDateTime::currentSecsSinceEpoch() + 2;
    if (!store.commit(13, source, serviceMetadata, accept, error)) return 107;
    const auto expiryPath = QDir(directory.path()).filePath("13.json");
    const auto priorExpiryEnvelope = readBytes(expiryPath);
    const auto expiringFetch = [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
                                   NekoGui_sub::SubscriptionDownload &download, QString &, const std::atomic_bool *) {
        download.source = updated;
        download.metadata = expiringMetadata;
        return true;
    };
    bool expiryValidatorCalled = false;
    const auto waitThroughExpiry = [&](const NekoGui_sub::ManagedProfile &, QString &) {
        expiryValidatorCalled = true;
        const auto expiryMs = *expiringMetadata.expiry * 1000;
        while (QDateTime::currentMSecsSinceEpoch() <= expiryMs)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return true;
    };
    QString expiryError;
    NekoGui_sub::SubscriptionService::CommittedSnapshot expiryCommitted;
    expiryCommitted.profile.source = "committed output sentinel";
    expiryCommitted.metadata.title = QStringLiteral("Output sentinel");
    if (NekoGui_sub::SubscriptionService::refresh(13, QUrl("https://example.invalid/expiring"), "0.1.0",
            copiedDirectory, store, expiringFetch, waitThroughExpiry, expiryError, nullptr, &expiryCommitted) ||
        !expiryValidatorCalled || expiryError.isEmpty() || readBytes(expiryPath) != priorExpiryEnvelope ||
        expiryCommitted.profile.source != "committed output sentinel" ||
        expiryCommitted.metadata.title != QStringLiteral("Output sentinel")) return 108;
    QTextStream(stdout) << "SUBSCRIPTION_EXPIRY_DURING_VALIDATION_PRESERVES_LAST_KNOWN_GOOD_PASS\n";
    // Characterize the boundary with a writer that bypasses SubscriptionService.
    // The store lock rejects a competing commit during validate+write, but
    // there is no lease between refresh returning its captured commit and a
    // later reconnect: a subsequent revocation writer may replace disk state.
    if (!store.commit(14, source, serviceMetadata, accept, error)) return 109;
    QSemaphore validationEntered, releaseValidation;
    const auto serviceCandidate = updated + "# captured before external revocation\n";
    NekoGui_sub::SubscriptionService::CommittedSnapshot capturedBeforeRevocation;
    QString captureError;
    bool captureSuccess = false;
    const NekoGui_sub::SubscriptionService::Fetcher captureFetch =
        [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
            NekoGui_sub::SubscriptionDownload &download, QString &, const std::atomic_bool *) {
            download.source = serviceCandidate;
            download.metadata = serviceMetadata;
            return true;
        };
    const NekoGui_sub::ManagedProfileStore::Validator blockingValidator =
        [&](const NekoGui_sub::ManagedProfile &, QString &) {
            validationEntered.release();
            return releaseValidation.tryAcquire(1, 10000);
        };
    std::thread captureThread([&] {
        captureSuccess = NekoGui_sub::SubscriptionService::refresh(14,
            QUrl("https://example.invalid/captured"), "0.1.0", copiedDirectory, store,
            captureFetch, blockingValidator, captureError, nullptr, &capturedBeforeRevocation);
    });
    const bool enteredValidation = validationEntered.tryAcquire(1, 5000);
    auto revokedMetadata = serviceMetadata;
    revokedMetadata.expiry = 1;
    int competingStoreValidatorCalls = 0;
    const auto competingStoreValidator = [&](const NekoGui_sub::ManagedProfile &, QString &) {
        ++competingStoreValidatorCalls;
        return true;
    };
    QString duringCommitError;
    const bool writeDuringCommit = store.commit(14, source, revokedMetadata, competingStoreValidator, duringCommitError);
    releaseValidation.release();
    captureThread.join();
    if (!enteredValidation || writeDuringCommit || duringCommitError.isEmpty() || competingStoreValidatorCalls != 0 ||
        !captureSuccess || capturedBeforeRevocation.profile.source != serviceCandidate) return 110;
    QString revokeError;
    if (!store.commit(14, source, revokedMetadata, accept, revokeError)) return 111;
    NekoGui_sub::ManagedProfile afterRevocation;
    NekoGui_sub::SubscriptionMetadata afterRevocationMetadata;
    if (!store.loadSnapshot(14, afterRevocation, afterRevocationMetadata, error) ||
        afterRevocation.source != source || afterRevocationMetadata.expiry != revokedMetadata.expiry ||
        capturedBeforeRevocation.profile.source != serviceCandidate ||
        capturedBeforeRevocation.metadata.expiry ||
        afterRevocation.sha256 == capturedBeforeRevocation.profile.sha256) return 112;
    QTextStream(stdout) << "SUBSCRIPTION_EXTERNAL_REVOCATION_AFTER_CAPTURE_IS_NOT_LATEST_WINS_PASS\n";
    if (committed.profile.source != source || committed.metadata.title != serviceMetadata.title ||
        committed.metadata.expiry || committed.metadata.upload != serviceMetadata.upload) return 104;
    QTextStream(stdout) << "SUBSCRIPTION_COMMITTED_SNAPSHOT_CAPTURE_PRESERVATION_PASS\n";
    QTextStream(stdout) << "SUBSCRIPTION_SERVICE_REFRESH_PASS\n";
    if (!store.loadSnapshot(10, profile, loadedMetadata, error) || profile.source != source ||
        loadedMetadata.title != serviceMetadata.title) return 41;
    const auto snapshotHash = profile.sha256;
    const auto snapshotTitle = loadedMetadata.title;
    auto replaceEnvelope = [&](const QJsonObject &object) {
        const auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
        QFile file(servicePath);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(bytes) == bytes.size();
    };
    const auto goodEnvelope = QJsonDocument::fromJson(serviceBytes).object();
    for (const auto &badMetadata : QList<QJsonValue>{
             QJsonObject{}, QJsonArray{QJsonArray{"Profile-Title"}},
             QJsonArray{QJsonArray{"Profile-Title", 1}},
             QJsonArray{QJsonArray{"Subscription-Userinfo", "total=-1"}},
             QJsonArray{QJsonArray{"Profile-Title", "a"}, QJsonArray{"profile-title", "b"}}}) {
        auto damaged = goodEnvelope;
        damaged["metadata"] = badMetadata;
        if (!replaceEnvelope(damaged)) return 42;
        const auto damagedBytes = readBytes(servicePath);
        if (store.loadSnapshot(10, profile, loadedMetadata, error) || profile.sha256 != snapshotHash ||
            loadedMetadata.title != snapshotTitle || store.load(10, profile, error) ||
            store.loadMetadata(10, loadedMetadata, error) ||
            store.commit(10, updated, serviceMetadata, accept, error) ||
            readBytes(servicePath) != damagedBytes) return 43;
    }
    auto oldEnvelope = goodEnvelope;
    oldEnvelope.remove("metadata");
    if (!replaceEnvelope(oldEnvelope) || !store.loadSnapshot(10, profile, loadedMetadata, error) ||
        profile.source != source || !loadedMetadata.title.isEmpty() || loadedMetadata.total) return 44;
    if (store.loadSnapshot(-1, profile, loadedMetadata, error) || profile.source != source) return 45;
    if (!replaceEnvelope(goodEnvelope)) return 46;
    QTextStream(stdout) << "MANAGED_SNAPSHOT_METADATA_INTEGRITY_PASS\n";
    if (NekoGui_sub::MihomoValidator::verifyExecutable(path, error) ||
        NekoGui_sub::MihomoValidator::verifyExecutable("missing.exe", error)) return 39;
    if (app.arguments().size() == 2) {
        const auto exe = app.arguments().at(1);
        if (!NekoGui_sub::MihomoValidator::validate(exe, projected, error)) return 59;
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
