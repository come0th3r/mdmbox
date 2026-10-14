#include "../../sub/SubscriptionDownloader.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QTextStream>
#include <QUuid>

class TlsServer : public QTcpServer {
public:
    QSslCertificate certificate;
    QSslKey key;
    int requests = 0;
    QByteArray lastRequest;
    void incomingConnection(qintptr descriptor) override {
        auto *socket = new QSslSocket(this);
        socket->setLocalCertificate(certificate);
        socket->setPrivateKey(key);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone); // Server does not request client certificates.
        if (!socket->setSocketDescriptor(descriptor)) { delete socket; return; }
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QSslSocket::readyRead, socket, [this, socket] {
            const auto input = socket->property("input").toByteArray() + socket->readAll();
            socket->setProperty("input", input);
            if (!input.contains("\r\n\r\n") || socket->property("sent").toBool()) return;
            socket->setProperty("sent", true);
            ++requests;
            lastRequest = input;
            QByteArray response;
            if (input.startsWith("GET /redirect "))
                response = "HTTP/1.1 302 Found\r\nLocation: https://localhost/never\r\nContent-Length: 0\r\n\r\n";
            else if (input.startsWith("GET /truncated "))
                response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nok";
            else if (input.startsWith("GET /chunked-large "))
                response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400001\r\n" +
                    QByteArray(4 * 1024 * 1024 + 1, 'a') + "\r\n0\r\n\r\n";
            else response = "HTTP/1.1 200 OK\r\nProfile-Update-Interval: 1\r\nContent-Length: 2\r\n\r\nok";
            socket->write(response);
            socket->disconnectFromHost();
        });
        socket->startServerEncryption();
    }
};

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    if (app.arguments().size() != 3 || !QSslSocket::supportsSsl()) return 1;
    QFile certFile(app.arguments()[1]), keyFile(app.arguments()[2]);
    if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) return 2;
    TlsServer server;
    server.certificate = QSslCertificate(certFile.readAll());
    server.key = QSslKey(keyFile.readAll(), QSsl::Rsa);
    if (server.certificate.isNull() || server.key.isNull() || !server.listen(QHostAddress::LocalHost, 0)) return 3;
    const auto originalSsl = QSslConfiguration::defaultConfiguration();
    auto trusted = originalSsl;
    trusted.setCaCertificates({server.certificate});
    QSslConfiguration::setDefaultConfiguration(trusted); // Process-local trust, not Windows certificate store.
    const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    auto request = [&](const QString &host, const QString &path) {
        return NekoGui_sub::ManagedSubscriptionRequest{
            QUrl(QString("https://%1:%2/%3").arg(host).arg(server.serverPort()).arg(path)), "MDMBOX/0.1.0 mihomo/1.19.32"};
    };
    NekoGui_sub::SubscriptionDownload result;
    QString error;
    if (!NekoGui_sub::SubscriptionDownloader::fetch(request("localhost", "ok"), id, result, error) ||
        result.source != "ok" || result.metadata.updateHours != 1 ||
        !server.lastRequest.contains("X-Hwid: " + id.toLatin1())) return 4;
    for (const auto &path : {"redirect", "truncated", "chunked-large"}) {
        const auto count = server.requests;
        if (NekoGui_sub::SubscriptionDownloader::fetch(request("localhost", path), id, result, error) ||
            error.isEmpty() || result.source != "ok" || server.requests != count + 1) return 5;
    }
    auto count = server.requests;
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("127.0.0.1", "ok"), id, result, error) ||
        result.source != "ok" || server.requests != count) return 6;
    auto untrusted = originalSsl;
    untrusted.setCaCertificates({});
    QSslConfiguration::setDefaultConfiguration(untrusted);
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("localhost", "ok"), id, result, error) ||
        result.source != "ok" || server.requests != count) return 7;
    QSslConfiguration::setDefaultConfiguration(originalSsl);
    QTextStream(stdout) << "TLS_TRUST_HOSTNAME_REDIRECT_TRUNCATION_CHUNKED_PASS\n";
    return 0;
}
