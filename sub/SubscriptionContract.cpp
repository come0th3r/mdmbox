#include "SubscriptionContract.hpp"

#include <QMap>
#include <QRegularExpression>
#include <QUrlQuery>
#include <limits>

namespace {
    bool number(const QByteArray &text, quint64 &result) {
        if (text.isEmpty()) return false;
        for (const auto c : text) if (c < '0' || c > '9') return false;
        bool ok = false;
        result = text.toULongLong(&ok);
        return ok;
    }

    bool webUrl(const QByteArray &value, QUrl &result) {
        const auto url = QUrl::fromEncoded(value, QUrl::StrictMode);
        if (!url.isValid() || url.host().isEmpty() || !url.userInfo().isEmpty() ||
            (url.scheme() != "https" && url.scheme() != "http")) return false;
        result = url;
        return true;
    }
}

namespace NekoGui_sub {
    bool SubscriptionMetadata::exhausted() const {
        if (!total || *total == 0 || !upload || !download) return false;
        // No addition overflow, even for two UINT64_MAX counters.
        return *upload >= *total || *download >= *total - *upload;
    }

    bool SubscriptionMetadata::expired(qint64 nowSeconds) const {
        return expiry && *expiry > 0 && nowSeconds >= *expiry;
    }

    bool SubscriptionMetadata::parse(const QList<QPair<QByteArray, QByteArray>> &headers,
                                     SubscriptionMetadata &result, QString &error) {
        error.clear();
        const QList<QByteArray> known{"subscription-userinfo", "profile-title", "profile-update-interval",
                                      "support-url", "profile-web-page-url"};
        QMap<QByteArray, QByteArray> values;
        for (const auto &header : headers) {
            const auto key = header.first.toLower();
            if (!known.contains(key)) continue;
            if (values.contains(key) || header.second.size() > 8192 || header.second.contains('\0') ||
                header.second.contains('\r') || header.second.contains('\n')) {
                error = QStringLiteral("Invalid or duplicate subscription metadata header");
                return false;
            }
            values.insert(key, header.second.trimmed());
        }
        SubscriptionMetadata candidate;
        if (values.contains("subscription-userinfo")) {
            QMap<QByteArray, quint64> fields;
            for (const auto &part : values.value("subscription-userinfo").split(';')) {
                if (part.trimmed().isEmpty()) continue;
                const auto equal = part.indexOf('=');
                if (equal < 1) {
                    error = QStringLiteral("Invalid subscription usage metadata");
                    return false;
                }
                const auto key = part.left(equal).trimmed().toLower();
                if (key != "upload" && key != "download" && key != "total" && key != "expire") continue;
                quint64 value;
                if (fields.contains(key) || !number(part.mid(equal + 1).trimmed(), value)) {
                    error = QStringLiteral("Invalid or duplicate subscription counter");
                    return false;
                }
                fields.insert(key, value);
            }
            if (fields.contains("upload")) candidate.upload = fields.value("upload");
            if (fields.contains("download")) candidate.download = fields.value("download");
            if (fields.contains("total")) candidate.total = fields.value("total");
            if (fields.contains("expire")) {
                const auto expiry = fields.value("expire");
                if (expiry > quint64(std::numeric_limits<qint64>::max())) {
                    error = QStringLiteral("Subscription expiry out of range");
                    return false;
                }
                candidate.expiry = qint64(expiry);
            }
        }
        if (values.contains("profile-update-interval")) {
            quint64 hours;
            if (!number(values.value("profile-update-interval"), hours) || hours == 0 || hours > 168) {
                error = QStringLiteral("Subscription update interval must be 1 to 168 hours");
                return false;
            }
            candidate.updateHours = int(hours);
        }
        if (values.contains("profile-title")) {
            auto bytes = values.value("profile-title");
            if (bytes.startsWith("base64:")) {
                const auto encoded = bytes.mid(7);
                const auto decoded = QByteArray::fromBase64Encoding(encoded, QByteArray::AbortOnBase64DecodingErrors);
                if (!decoded) {
                    error = QStringLiteral("Invalid subscription title encoding");
                    return false;
                }
                bytes = decoded.decoded;
            }
            const auto text = QString::fromUtf8(bytes);
            if (text.toUtf8() != bytes || text.size() > 1024) {
                error = QStringLiteral("Invalid subscription title");
                return false;
            }
            for (const auto c : text) {
                if (c.unicode() < 32 || c.unicode() == 127) {
                    error = QStringLiteral("Invalid subscription title control character");
                    return false;
                }
            }
            candidate.title = text;
        }
        for (const auto &key : {QByteArray("support-url"), QByteArray("profile-web-page-url")}) {
            if (!values.contains(key)) continue;
            auto &target = key == "support-url" ? candidate.supportUrl : candidate.pageUrl;
            if (!webUrl(values.value(key), target)) {
                error = QStringLiteral("Invalid subscription metadata web URL");
                return false;
            }
        }
        result = std::move(candidate);
        return true;
    }

    bool ManagedSubscriptionRequest::build(const QUrl &url, const QString &appVersion, const QString &coreVersion,
                                           ManagedSubscriptionRequest &result, QString &error) {
        error.clear();
        static const QRegularExpression version(QStringLiteral("^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$"));
        if (!url.isValid() || url.scheme() != "https" || url.host().isEmpty() ||
            !url.userInfo().isEmpty() || url.hasFragment() || !version.match(appVersion).hasMatch() ||
            !version.match(coreVersion).hasMatch()) {
            error = QStringLiteral("HTTPS subscription URL and verified version strings required");
            return false;
        }
        ManagedSubscriptionRequest candidate;
        candidate.url = url;
        QUrlQuery query(url);
        query.removeAllQueryItems("format");
        query.addQueryItem("format", "clash");
        candidate.url.setQuery(query);
        candidate.userAgent = QStringLiteral("MDMBOX/%1 mihomo/%2").arg(appVersion, coreVersion).toLatin1();
        result = std::move(candidate);
        return true;
    }
}
