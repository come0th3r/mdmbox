#include "ManagedRuntimePolicy.hpp"
#include <QSet>
#include <QRegularExpression>
#include <yaml-cpp/yaml.h>

namespace {
    bool onlyKeys(const YAML::Node &node, const QSet<QString> &allowed) {
        if (!node.IsMap()) return false;
        for (const auto &entry : node) {
            if (!entry.first.IsScalar() || !allowed.contains(QString::fromStdString(entry.first.Scalar()))) return false;
        }
        return true;
    }

    // Deliberately narrow first execution contract, not protocol capability detection.
    bool reviewedNestedOptions(const YAML::Node &root) {
        for (const auto &proxy : root["proxies"]) {
            if (!onlyKeys(proxy, {"name", "type", "server", "port", "username", "password", "udp"}) ||
                proxy["type"].Scalar() != "socks5" || !proxy["server"].IsScalar() || !proxy["port"].IsScalar()) return false;
            for (const auto &entry : proxy) if (!entry.second.IsScalar()) return false;
        }
        QSet<QString> targets{"DIRECT", "REJECT"};
        for (const auto &proxy : root["proxies"]) targets.insert(QString::fromStdString(proxy["name"].Scalar()));
        // No group-to-group references yet: avoid selector cycles before lifecycle is implemented.
        for (const auto &group : root["proxy-groups"]) {
            if (!onlyKeys(group, {"name", "type", "proxies"}) || group["type"].Scalar() != "select" ||
                !group["proxies"].IsSequence() || group["proxies"].size() == 0) return false;
            for (const auto &member : group["proxies"]) {
                if (!member.IsScalar() || !targets.contains(QString::fromStdString(member.Scalar()))) return false;
            }
        }
        if (!onlyKeys(root["dns"], {"enable", "ipv6", "nameserver", "default-nameserver", "listen"})) return false;
        for (const auto &entry : root["dns"]) {
            const auto key = entry.first.Scalar();
            if (key == "nameserver" || key == "default-nameserver") {
                if (!entry.second.IsSequence()) return false;
                for (const auto &server : entry.second) {
                    if (!server.IsScalar()) return false;
                    // Initial smoke resolves with plain IP resolvers only: no URL/file/group directives.
                    static const QRegularExpression ipv4(QStringLiteral("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"));
                    if (!ipv4.match(QString::fromStdString(server.Scalar())).hasMatch()) return false;
                }
            } else if (!entry.second.IsScalar()) return false;
        }
        if (root["hosts"].IsDefined()) return false;
        if (root["profile"].IsDefined() &&
            !onlyKeys(root["profile"], {"store-selected", "store-fake-ip"})) return false;
        return true;
    }
}

namespace NekoGui_sub {
    bool ManagedRuntimePolicy::projectLoopback(const ManagedProfile &profile, int mixedPort, int controllerPort,
                                               const QByteArray &apiToken, ManagedProfile &result, QString &error) {
        error.clear();
        static const QRegularExpression token(QStringLiteral("^[a-f0-9]{64}$"));
        if (mixedPort < 1024 || mixedPort > 65535 || controllerPort < 1024 || controllerPort > 65535 ||
            mixedPort == controllerPort || !token.match(QString::fromLatin1(apiToken)).hasMatch()) {
            error = QStringLiteral("Distinct unprivileged loopback ports and fresh API token required");
            return false;
        }
        if (!checkSelfContained(profile, error)) return false;
        try {
            auto root = YAML::Load(profile.source.toStdString());
            if (!reviewedNestedOptions(root)) {
                error = QStringLiteral("Nested options are outside the initial SOCKS/select runtime contract");
                return false;
            }
            const QSet<QString> allowed{
                "proxies", "proxy-groups", "rules", "dns", "hosts", "profile",
                "mixed-port", "port", "socks-port", "redir-port", "tproxy-port", "allow-lan",
                "bind-address", "mode", "log-level", "ipv6", "unified-delay", "tcp-concurrent"};
            for (const auto &entry : root) {
                if (!allowed.contains(QString::fromStdString(entry.first.Scalar()))) {
                    error = QStringLiteral("Unreviewed top-level field requires runtime projection policy");
                    return false;
                }
            }
            // Retain panel routing/proxy/DNS semantics; only own local runtime controls.
            root["mixed-port"] = mixedPort;
            root["port"] = 0;
            root["socks-port"] = 0;
            root["redir-port"] = 0;
            root["tproxy-port"] = 0;
            root["allow-lan"] = false;
            root["bind-address"] = "127.0.0.1";
            root["mode"] = "rule";
            root["log-level"] = "silent";
            root["external-controller"] = "127.0.0.1:" + std::to_string(controllerPort);
            root["secret"] = apiToken.toStdString();
            root["tun"]["enable"] = false;
            root["dns"].remove("listen");
            root["dns"]["use-hosts"] = false;
            root["dns"]["use-system-hosts"] = false;
            // Selection/FakeIP persistence belongs in an explicit future managed home policy.
            root["profile"]["store-selected"] = false;
            root["profile"]["store-fake-ip"] = false;
            YAML::Emitter emitter;
            emitter << root;
            if (!emitter.good()) {
                error = QStringLiteral("Managed loopback projection emission failed");
                return false;
            }
            return ManagedProfile::ParseMihomo(QByteArray(emitter.c_str(), int(emitter.size())), result, error);
        } catch (const YAML::Exception &) {
            error = QStringLiteral("Managed loopback projection failed");
            return false;
        }
    }

    bool ManagedRuntimePolicy::checkSelfContained(const ManagedProfile &profile, QString &error) {
        ManagedProfile checked;
        if (!ManagedProfile::ParseMihomo(profile.source, checked, error)) return false;
        try {
            const auto root = YAML::Load(profile.source.toStdString());
            // Presence is refused even if disabled: source is retained, never silently stripped.
            for (const auto *key : {"proxy-providers", "rule-providers", "geox-url", "geodata-loader",
                                    "external-ui", "external-ui-url", "external-ui-name", "external-controller",
                                    "external-controller-tls", "external-controller-unix", "external-controller-pipe",
                                    "external-doh-server", "secret", "authentication", "listeners", "tunnels",
                                    "tun", "iptables", "routing-mark", "interface-name"}) {
                if (root[key].IsDefined()) {
                    error = QStringLiteral("Profile requires resource provisioning or local runtime projection");
                    return false;
                }
            }
            // A nested rule (AND/OR/NOT) may reference GEOIP/GEOSITE/RULE-SET too.
            for (const auto &rule : checked.rules) {
                const auto upper = rule.toUpper();
                if (upper.contains("GEOIP,") || upper.contains("GEOSITE,") || upper.contains("RULE-SET,")) {
                    error = QStringLiteral("Profile requires provisioned routing resources");
                    return false;
                }
            }
            // DNS policies/filters can reference geodata independently of routing rules.
            const auto dns = root["dns"];
            if (dns["nameserver-policy"].IsDefined() || dns["fallback-filter"].IsDefined() ||
                dns["use-hosts"].IsDefined() || dns["use-system-hosts"].IsDefined()) {
                error = QStringLiteral("Profile DNS requires explicit runtime resource policy");
                return false;
            }
            error.clear();
            return true;
        } catch (const YAML::Exception &) {
            error = QStringLiteral("Unable to inspect managed runtime requirements");
            return false;
        }
    }
}
