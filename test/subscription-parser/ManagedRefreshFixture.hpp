#pragma once

#include "sub/ManagedProfileStore.hpp"
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QUrlQuery>

// Synthetic TLS origin only. No production TLS bypass or system trust installation.
class ManagedRefreshFixture : public QTcpServer {
public:
    QSslCertificate certificate;
    QSslKey key;
    QByteArray body;
    QByteArray lastRequest;
    int requests = 0;
    qint64 expiry = 0;

    void incomingConnection(qintptr descriptor) override {
        auto *socket = new QSslSocket(this);
        socket->setLocalCertificate(certificate);
        socket->setPrivateKey(key);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone); // No client certificate required.
        if (!socket->setSocketDescriptor(descriptor)) { delete socket; return; }
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QSslSocket::readyRead, socket, [this, socket] {
            const auto input = socket->property("input").toByteArray() + socket->readAll();
            socket->setProperty("input", input);
            if (!input.contains("\r\n\r\n") || socket->property("sent").toBool()) return;
            socket->setProperty("sent", true);
            lastRequest = input;
            ++requests;
            socket->write("HTTP/1.1 200 OK\r\nProfile-Update-Interval: 1\r\n"
                          "Subscription-Userinfo: upload=4294967296; download=1; total=0; expire=" +
                          QByteArray::number(expiry) + "\r\n"
                          "Profile-Title: base64:U3ludGhldGlj\r\nContent-Length: " +
                          QByteArray::number(body.size()) + "\r\n\r\n" + body);
            socket->disconnectFromHost();
        });
        socket->startServerEncryption();
    }
};

inline bool testManagedHttpsRefresh(const QString &certPath, const QString &keyPath,
                                   const std::shared_ptr<NekoGui::Group> &group,
                                   const std::function<bool()> &unchanged) {
    QFile certFile(certPath), keyFile(keyPath);
    if (!QSslSocket::supportsSsl() || !certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) return false;
    ManagedRefreshFixture server;
    server.certificate = QSslCertificate(certFile.readAll());
    server.key = QSslKey(keyFile.readAll(), QSsl::Rsa);
    if (server.certificate.isNull() || server.key.isNull() || !server.listen(QHostAddress::LocalHost, 0)) return false;
    const auto originalSsl = QSslConfiguration::defaultConfiguration();
    struct RestoreTrust {
        QSslConfiguration configuration;
        ~RestoreTrust() { QSslConfiguration::setDefaultConfiguration(configuration); }
    } restore{originalSsl};
    auto trusted = originalSsl;
    trusted.setCaCertificates({server.certificate});
    QSslConfiguration::setDefaultConfiguration(trusted);
    const QByteArray source =
        "# synthetic full document\n"
        "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 12345}]\n"
        "proxy-groups: [{name: select, type: select, proxies: [node]}]\n"
        "rules: ['MATCH,select']\n"
        "dns: {enable: true, nameserver: [127.0.0.1]}\n";
    server.body = source;
    group->url = QString("https://localhost:%1/custom/synthetic?keep=a%2Fb&format=uri&format=yaml").arg(server.serverPort());
    group->Save();
    auto readBytes = [](const QString &path) {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{};
    };
    const auto groupBytes = readBytes(group->fn);
    NekoGui_sub::GroupUpdater updater;
    updater.Update(group->url, group->id, false);
    QTextStream(stdout) << "HTTPS_REFRESH_STAGE downloaded=" << server.requests << "\n";
    NekoGui_sub::ManagedProfileStore store("managed-subscriptions");
    NekoGui_sub::ManagedProfile profile;
    NekoGui_sub::SubscriptionMetadata metadata;
    QString error;
    if (server.requests != 1 || !unchanged() || readBytes(group->fn) != groupBytes ||
        !store.loadSnapshot(group->id, profile, metadata, error) || profile.source != source ||
        metadata.title != "Synthetic" || metadata.upload != quint64(4294967296) ||
        metadata.total != quint64(0) || metadata.updateHours != 1) {
        QTextStream(stderr) << "HTTPS_REFRESH_STAGE snapshot failed: " << error << "\n";
        return false;
    }
    const auto requestLines = server.lastRequest.split('\n');
    const auto target = requestLines.first().split(' ').value(1);
    const auto requestUrl = QUrl::fromEncoded(target);
    if (requestUrl.path() != "/custom/synthetic" ||
        QUrlQuery(requestUrl).allQueryItemValues("format") != QStringList{"clash"} ||
        QUrlQuery(requestUrl).queryItemValue("keep", QUrl::FullyDecoded) != "a/b" ||
        !server.lastRequest.contains(QByteArray("User-Agent: MDMBOX/") + NKR_VERSION + " mihomo/1.19.32")) {
        QTextStream(stderr) << "HTTPS_REFRESH_STAGE request contract failed\n";
        return false;
    }
    auto hwid = [](const QByteArray &request) {
        for (const auto &line : request.split('\n'))
            if (line.toLower().startsWith("x-hwid:")) return line.mid(7).trimmed();
        return QByteArray{};
    };
    const auto firstId = hwid(server.lastRequest);
    if (firstId.size() != 36) return false;
    const auto envelopePath = "managed-subscriptions/" + QString::number(group->id) + ".json";
    const auto firstEnvelope = readBytes(envelopePath);
    // Actual config-check rejection, not injected callback.
    server.body.replace("type: socks5", "type: deliberately-unsupported");
    updater.Update(group->url, group->id, false);
    if (server.requests != 2 || readBytes(envelopePath) != firstEnvelope || !unchanged() ||
        readBytes(group->fn) != groupBytes || hwid(server.lastRequest) != firstId) return false;
    server.body = QStringLiteral("proxies: [{name: '⛔ This device is blocked', type: socks5, server: 127.0.0.1, port: 1}]\n"
        "proxy-groups: [{name: select, type: select, proxies: ['⛔ This device is blocked']}]\n"
        "rules: ['MATCH,select']\n").toUtf8();
    updater.Update(group->url, group->id, false);
    if (server.requests != 3 || readBytes(envelopePath) != firstEnvelope || !unchanged() ||
        readBytes(group->fn) != groupBytes || hwid(server.lastRequest) != firstId) return false;
    server.body = source + "# second generation\n";
    updater.Update(group->url, group->id, false);
    return server.requests == 4 && unchanged() && readBytes(group->fn) == groupBytes &&
        hwid(server.lastRequest) == firstId && readBytes(envelopePath + ".previous") == firstEnvelope &&
        store.loadSnapshot(group->id, profile, metadata, error) && profile.source == server.body && metadata.title == "Synthetic";
}
