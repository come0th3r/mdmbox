#pragma once

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QUrl>
#include <optional>

namespace NekoGui_sub {
    struct SubscriptionMetadata {
        std::optional<quint64> upload;
        std::optional<quint64> download;
        // Missing is unknown; zero is unlimited, not exhausted.
        std::optional<quint64> total;
        std::optional<qint64> expiry;
        std::optional<int> updateHours;
        QString title;
        QUrl supportUrl;
        QUrl pageUrl;

        bool exhausted() const;
        bool expired(qint64 nowSeconds) const;
        static bool parse(const QList<QPair<QByteArray, QByteArray>> &headers,
                          SubscriptionMetadata &result, QString &error);
    };

    struct ManagedSubscriptionRequest {
        QUrl url;
        QByteArray userAgent;
        static bool build(const QUrl &url, const QString &appVersion, const QString &coreVersion,
                          ManagedSubscriptionRequest &result, QString &error);
    };
}
