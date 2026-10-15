#include "ManagedControllerProbe.hpp"
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QRegularExpression>
#include <QTimer>

namespace NekoGui_sub {
    ManagedControllerProbe::Result ManagedControllerProbe::version(int port, const QByteArray &token, int timeoutMs) {
        static const QRegularExpression tokenPattern(QStringLiteral("^[0-9a-f]{64}$"));
        if (port < 1024 || port > 65535 || timeoutMs < 1 || timeoutMs > 500 ||
            !tokenPattern.match(QString::fromLatin1(token)).hasMatch()) return Result::Rejected;
        QNetworkAccessManager manager;
        manager.setProxy(QNetworkProxy::NoProxy);
        QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:%1/version").arg(port)));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        request.setRawHeader("Authorization", "Bearer " + token);
        auto *reply = manager.get(request);
        reply->setReadBufferSize(4096);
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QByteArray body;
        bool oversized = false;
        const auto collect = [&] {
            if (oversized || !reply->isOpen()) return;
            body += reply->read(4097 - body.size());
            if (body.size() > 4096) { oversized = true; reply->abort(); }
        };
        QObject::connect(reply, &QNetworkReply::readyRead, &loop, collect);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
        timeout.start(timeoutMs);
        if (!reply->isFinished()) loop.exec();
        collect();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool accepted = !oversized && reply->error() == QNetworkReply::NoError && status == 200 &&
            QJsonDocument::fromJson(body).object().value(QStringLiteral("version")).toString() == QStringLiteral("v1.19.32");
        const auto result = accepted ? Result::Accepted :
            (oversized || status != 0 ? Result::Rejected : Result::Retry);
        delete reply;
        return result;
    }
}
