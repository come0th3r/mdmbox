#include "ManagedRuntimePolicy.hpp"
#include <yaml-cpp/yaml.h>

namespace NekoGui_sub {
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
