#include "ManagedRuntimePolicy.hpp"
#include <QSet>
#include <QRegularExpression>
#include <yaml-cpp/yaml.h>

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
