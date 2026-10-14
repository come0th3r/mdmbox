#include "ManagedProfile.hpp"

#include <QCryptographicHash>
#include <QSet>
#include <yaml-cpp/yaml.h>

namespace {
    // Bound traversal, including aliases, and reject ambiguous duplicate map keys.
    bool inspect(const YAML::Node &node, int depth, int &remaining) {
        if (depth > 64 || --remaining < 0) return false;
        if (node.IsMap()) {
            QSet<QString> keys;
            for (const auto &entry : node) {
                if (!entry.first.IsScalar()) return false;
                const auto key = QString::fromStdString(entry.first.Scalar());
                if (keys.contains(key)) return false;
                keys.insert(key);
                if (!inspect(entry.second, depth + 1, remaining)) return false;
            }
        } else if (node.IsSequence()) {
            for (const auto &entry : node) {
                if (!inspect(entry, depth + 1, remaining)) return false;
            }
        }
        return true;
    }

    bool names(const YAML::Node &items, QStringList &result) {
        if (!items.IsSequence()) return false;
        QSet<QString> seen;
        for (const auto &item : items) {
            if (!item.IsMap() || !item["name"].IsScalar() || !item["type"].IsScalar()) return false;
            const auto name = QString::fromStdString(item["name"].Scalar());
            if (name.trimmed().isEmpty() || seen.contains(name)) return false;
            seen.insert(name);
            result.append(name);
        }
        return true;
    }
}

namespace NekoGui_sub {
    bool ManagedProfile::ParseMihomo(const QByteArray &source, ManagedProfile &result, QString &error) {
        error.clear();
        // Leave result untouched on every failure. Never log remote content.
        if (source.isEmpty() || source.size() > 4 * 1024 * 1024 || source.contains('\0') ||
            QString::fromUtf8(source).toUtf8() != source) {
            error = QStringLiteral("Invalid or oversized UTF-8 profile");
            return false;
        }
        try {
            const auto documents = YAML::LoadAll(source.toStdString());
            int remaining = 100000;
            if (documents.size() != 1 || !documents.front().IsMap() ||
                !inspect(documents.front(), 0, remaining)) {
                error = QStringLiteral("Expected one unambiguous bounded YAML mapping");
                return false;
            }
            const auto root = documents.front();
            ManagedProfile candidate;
            if (!names(root["proxies"], candidate.proxyNames) || candidate.proxyNames.isEmpty() ||
                !names(root["proxy-groups"], candidate.groupNames) || candidate.groupNames.isEmpty() ||
                !root["rules"].IsSequence() || root["rules"].size() == 0 || !root["dns"].IsMap()) {
                error = QStringLiteral("Expected full mihomo proxies, proxy-groups, rules and DNS");
                return false;
            }
            QSet<QString> allNames;
            for (const auto &name : candidate.proxyNames + candidate.groupNames) {
                if (allNames.contains(name)) {
                    error = QStringLiteral("Proxy and group names must be distinct");
                    return false;
                }
                allNames.insert(name);
            }
            for (const auto &rule : root["rules"]) {
                if (!rule.IsScalar() || rule.Scalar().empty()) {
                    error = QStringLiteral("Rules must be nonempty scalars in panel order");
                    return false;
                }
                candidate.rules.append(QString::fromStdString(rule.Scalar()));
            }
            for (const auto *key : {"rule-providers", "proxy-providers"}) {
                if (root[key].IsDefined() && !root[key].IsMap()) {
                    error = QStringLiteral("Provider section must be a mapping");
                    return false;
                }
            }
            candidate.source = source; // No re-emission: retain unknown fields and exact bytes.
            candidate.sha256 = QCryptographicHash::hash(source, QCryptographicHash::Sha256).toHex();
            result = std::move(candidate);
            return true;
        } catch (const YAML::Exception &) {
            error = QStringLiteral("Invalid mihomo YAML document");
            return false;
        }
    }
}
