#include "SubscriptionDownloader.hpp"

#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTimer>
#include <QUuid>

namespace NekoGui_sub {
    bool SubscriptionDownloader::fetch(const ManagedSubscriptionRequest &request, const QString &installationId,
                                        SubscriptionDownload &result, QString &error,
                                        const std::atomic_bool *cancel, int timeoutMs) {
        error.clear();
        const auto &url = request.url;
        bool allowed = url.scheme() == "https";
#ifdef MDMBOX_DOWNLOADER_LOOPBACK_TEST
        allowed = allowed || (url.scheme() == "http" && url.host() == "127.0.0.1");
#endif
        if (!allowed || !url.isValid() || url.host().isEmpty() || !url.userInfo().isEmpty() || url.hasFragment() ||
            request.userAgent.isEmpty() || request.userAgent.size() > 256 || request.userAgent.contains('\r') ||
            request.userAgent.contains('\n') || request.userAgent.contains('\0') || timeoutMs < 1 || timeoutMs > 60000 ||
            QUuid(installationId).isNull() || QUuid(installationId).toString(QUuid::WithoutBraces) != installationId) {
            error = QStringLiteral("Invalid managed subscription download request");
            return false;
        }
        if (cancel && cancel->load()) {
            error = QStringLiteral("Subscription download cancelled");
            return false;
        }
        QNetworkAccessManager manager;
        manager.setProxy(QNetworkProxy::NoProxy); // Never silently inherit a user/machine proxy.
        QNetworkRequest networkRequest(url);
        networkRequest.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        networkRequest.setRawHeader("User-Agent", request.userAgent);
        networkRequest.setRawHeader("X-Hwid", installationId.toLatin1());
        networkRequest.setRawHeader("X-Device-Os", "Windows");
        networkRequest.setRawHeader("Accept", "application/yaml, text/yaml, text/plain");
        networkRequest.setRawHeader("Cache-Control", "no-cache");
        auto ssl = QSslConfiguration::defaultConfiguration();
        ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
        networkRequest.setSslConfiguration(ssl);
        auto *reply = manager.get(networkRequest);
        reply->setReadBufferSize(64 * 1024);
        QEventLoop loop;
        QTimer deadline;
        QTimer cancellation;
        QByteArray bytes;
        constexpr qsizetype MaxBytes = 4 * 1024 * 1024;
        auto reject = [&](const QString &reason) {
            if (error.isEmpty()) error = reason;
            reply->abort();
        };
        auto drain = [&] {
            while (reply->bytesAvailable() > 0 && error.isEmpty()) {
                const auto chunk = reply->read(qMin<qint64>(65536, MaxBytes - bytes.size() + 1));
                bytes += chunk;
                if (bytes.size() > MaxBytes) reject(QStringLiteral("Subscription response exceeds size limit"));
                if (chunk.isEmpty()) break;
            }
        };
        QObject::connect(reply, &QNetworkReply::readyRead, &loop, drain);
        QObject::connect(reply, &QNetworkReply::metaDataChanged, &loop, [&] {
            if (reply->header(QNetworkRequest::ContentLengthHeader).toLongLong() > MaxBytes)
                reject(QStringLiteral("Subscription response exceeds size limit"));
        });
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&] { reject(QStringLiteral("Subscription download timed out")); });
        QObject::connect(&cancellation, &QTimer::timeout, &loop, [&] {
            if (cancel && cancel->load()) reject(QStringLiteral("Subscription download cancelled"));
        });
        deadline.start(timeoutMs);
        if (cancel) cancellation.start(25);
        if (!reply->isFinished()) loop.exec();
        deadline.stop();
        cancellation.stop();
        drain();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (error.isEmpty() && status >= 300 && status < 400)
            error = QStringLiteral("Subscription redirect requires explicit approval");
        if (error.isEmpty() && (reply->error() != QNetworkReply::NoError || status != 200))
            error = QStringLiteral("Subscription transport or HTTP request failed");
        if (error.isEmpty() && bytes.trimmed().isEmpty()) error = QStringLiteral("Empty subscription response");
        SubscriptionDownload candidate;
        if (error.isEmpty() && !SubscriptionMetadata::parse(reply->rawHeaderPairs(), candidate.metadata, error)) {
            // Metadata parsing already supplies a content-free reason.
        }
        delete reply;
        if (!error.isEmpty()) return false;
        candidate.source = std::move(bytes);
        result = std::move(candidate);
        return true;
    }
}
