#include "../../sub/ManagedProfile.hpp"
#include <QCoreApplication>
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
    return 0;
}
