#include "HTTPRequestHelper.hpp"

#include <QByteArray>
#include <QEventLoop>
#include <QMetaEnum>
#include <QNetworkProxy>
#include <QSysInfo>
#include <QThread>
#include <QTimer>

#include "main/NekoGui.hpp"

namespace NekoGui_network {
    namespace {
        QByteArray normalizeHeaderName(QString name) {
            name = name.trimmed().replace("_", "-");
            auto lowered = name.toLower();
            if (lowered == "ua") lowered = "user-agent";
            if (lowered == "refer") lowered = "referer";
            if (lowered == "useragent") lowered = "user-agent";
            if (lowered == "acceptlanguage") lowered = "accept-language";
            if (lowered == "cachecontrol") lowered = "cache-control";

            QStringList parts;
            for (const auto &part: lowered.split("-", Qt::SkipEmptyParts)) {
                if (part.length() <= 2) {
                    parts << part.toUpper();
                } else {
                    auto normalized = part;
                    normalized[0] = normalized[0].toUpper();
                    parts << normalized;
                }
            }
            return parts.join("-").toUtf8();
        }

        QString decodeHeaderValue(QString value) {
            value = value.trimmed();
            value.replace("\\|", "|");
            return QUrl::fromPercentEncoding(value.toUtf8());
        }

        bool hasHeader(const QList<QPair<QByteArray, QByteArray>> &headers, const QByteArray &name) {
            for (const auto &header: headers) {
                if (QString::fromUtf8(header.first).compare(QString::fromUtf8(name), Qt::CaseInsensitive) == 0) {
                    return true;
                }
            }
            return false;
        }
    } // namespace

    ParsedSubscriptionRequest NetworkRequestHelper::ParseSubscriptionRequest(const QString &rawUrl) {
        ParsedSubscriptionRequest parsed;

        const auto parts = rawUrl.split("|", Qt::KeepEmptyParts);
        const auto baseUrl = parts.value(0).trimmed();
        parsed.url = QUrl(baseUrl);
        if (!parsed.url.isValid() || parsed.url.scheme().isEmpty()) {
            parsed.url = QUrl::fromUserInput(baseUrl);
        }

        for (int i = 1; i < parts.length(); ++i) {
            auto header = parts[i].trimmed();
            if (header.isEmpty()) continue;
            const auto splitIndex = header.indexOf('=');
            if (splitIndex <= 0) continue;

            const auto key = normalizeHeaderName(header.left(splitIndex));
            if (key.isEmpty()) continue;
            const auto value = decodeHeaderValue(header.mid(splitIndex + 1));
            parsed.headers.append({key, value.toUtf8()});
        }

        return parsed;
    }

    QString NetworkRequestHelper::GetSubscriptionBaseUrl(const QString &rawUrl) {
        return ParseSubscriptionRequest(rawUrl).url.toString();
    }

    QString NetworkRequestHelper::GetSubscriptionHost(const QString &rawUrl) {
        return ParseSubscriptionRequest(rawUrl).url.host();
    }

    NekoHTTPResponse NetworkRequestHelper::HttpGet(const QString &rawUrl) {
        const auto parsed = ParseSubscriptionRequest(rawUrl);
        if (!parsed.url.isValid() || parsed.url.scheme().isEmpty()) {
            return NekoHTTPResponse{QObject::tr("Invalid subscription URL.")};
        }

        NekoHTTPResponse lastError;
        for (int attempt = 0; attempt < 2; ++attempt) {
            QNetworkRequest request;
            QNetworkAccessManager accessManager;
            request.setUrl(parsed.url);

            if (NekoGui::dataStore->sub_use_proxy) {
                QNetworkProxy p;
                // Note: sing-box mixed socks5 protocol error
                p.setType(QNetworkProxy::HttpProxy);
                p.setHostName("127.0.0.1");
                p.setPort(NekoGui::dataStore->inbound_socks_port);
                if (NekoGui::dataStore->inbound_auth->NeedAuth()) {
                    p.setUser(NekoGui::dataStore->inbound_auth->username);
                    p.setPassword(NekoGui::dataStore->inbound_auth->password);
                }
                accessManager.setProxy(p);
                if (NekoGui::dataStore->started_id < 0) {
                    return NekoHTTPResponse{QObject::tr("Request with proxy but no profile started.")};
                }
            }
            if (accessManager.proxy().type() == QNetworkProxy::Socks5Proxy) {
                auto cap = accessManager.proxy().capabilities();
                accessManager.proxy().setCapabilities(cap | QNetworkProxy::HostNameLookupCapability);
            }

#if (QT_VERSION >= QT_VERSION_CHECK(5, 9, 0))
            request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
#endif

            if (!hasHeader(parsed.headers, "User-Agent")) {
                request.setHeader(QNetworkRequest::KnownHeaders::UserAgentHeader, NekoGui::dataStore->GetUserAgent());
            }
            if (!hasHeader(parsed.headers, "Accept")) {
                request.setRawHeader("Accept", "application/json, application/yaml, text/yaml, text/plain, */*");
            }
            if (!hasHeader(parsed.headers, "Cache-Control")) {
                request.setRawHeader("Cache-Control", "no-cache");
            }
            if (!hasHeader(parsed.headers, "X-Hwid")) {
                request.setRawHeader("X-Hwid", QSysInfo::machineUniqueId());
            }
            for (const auto &header: parsed.headers) {
                request.setRawHeader(header.first, header.second);
            }

            if (NekoGui::dataStore->sub_insecure) {
                QSslConfiguration c;
                c.setPeerVerifyMode(QSslSocket::PeerVerifyMode::VerifyNone);
                request.setSslConfiguration(c);
            }

            auto reply = accessManager.get(request);
            connect(reply, &QNetworkReply::sslErrors, reply, [](const QList<QSslError> &errors) {
                QStringList error_str;
                for (const auto &err: errors) {
                    error_str << err.errorString();
                }
                MW_show_log(QStringLiteral("SSL Errors: %1 %2").arg(error_str.join(","), NekoGui::dataStore->sub_insecure ? "(Ignored)" : ""));
            });

            auto abortTimer = new QTimer;
            abortTimer->setSingleShot(true);
            abortTimer->setInterval(15000);
            QObject::connect(abortTimer, &QTimer::timeout, reply, &QNetworkReply::abort);
            abortTimer->start();
            {
                QEventLoop loop;
                QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
                loop.exec();
            }
            abortTimer->stop();
            abortTimer->deleteLater();

            auto result = NekoHTTPResponse{
                reply->error() == QNetworkReply::NetworkError::NoError ? "" : reply->errorString(),
                reply->readAll(),
                reply->rawHeaderPairs(),
            };
            const auto statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const auto reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
            if (result.error.isEmpty() && statusCode >= 400) {
                result.error = QStringLiteral("HTTP %1 %2").arg(statusCode).arg(reason);
            }
            reply->deleteLater();

            if (result.error.isEmpty()) {
                return result;
            }

            lastError = result;
            if (attempt == 0) {
                MW_show_log(QObject::tr("Subscription request failed, retrying once: %1").arg(result.error));
                QThread::msleep(250);
            }
        }

        return lastError;
    }

    NekoHTTPResponse NetworkRequestHelper::HttpGet(const QUrl &url) {
        return HttpGet(url.toString());
    }

    QString NetworkRequestHelper::GetHeader(const QList<QPair<QByteArray, QByteArray>> &header, const QString &name) {
        for (const auto &p: header) {
            if (QString(p.first).toLower() == name.toLower()) return p.second;
        }
        return "";
    }

} // namespace NekoGui_network
