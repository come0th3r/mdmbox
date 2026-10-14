#include "../../sub/SubscriptionDownloader.hpp"
#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUuid>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) return 1;
    QByteArray received;
    QObject::connect(&server, &QTcpServer::newConnection, &app, [&] {
        while (server.hasPendingConnections()) {
            auto *socket = server.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
                auto input = socket->property("input").toByteArray() + socket->readAll();
                socket->setProperty("input", input);
                if (!input.contains("\r\n\r\n") || socket->property("sent").toBool()) return;
                socket->setProperty("sent", true);
                received = input;
                if (input.startsWith("GET /hang ")) return;
                QByteArray response;
                if (input.startsWith("GET /redirect ")) response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/never\r\nContent-Length: 0\r\n\r\n";
                else if (input.startsWith("GET /large ")) response = "HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n";
                else if (input.startsWith("GET /empty ")) response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                else if (input.startsWith("GET /badmeta ")) response = "HTTP/1.1 200 OK\r\nSubscription-Userinfo: total=-1\r\nContent-Length: 2\r\n\r\nok";
                else if (input.startsWith("GET /denied ")) response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno";
                else response = "HTTP/1.1 200 OK\r\nProfile-Update-Interval: 1\r\nContent-Length: 2\r\n\r\nok";
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });
    const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    auto request = [&](const QString &path) {
        return NekoGui_sub::ManagedSubscriptionRequest{QUrl(QString("http://127.0.0.1:%1/%2").arg(server.serverPort()).arg(path)), "MDMBOX/0.1.0 mihomo/1.19.32"};
    };
    NekoGui_sub::SubscriptionDownload result;
    QString error;
    if (!NekoGui_sub::SubscriptionDownloader::fetch(request("ok"), id, result, error) || result.source != "ok" ||
        result.metadata.updateHours != 1 || !received.contains("X-Hwid: " + id.toLatin1())) return 2;
    for (const auto &path : {"redirect", "large", "empty", "badmeta", "denied", "hang"}) {
        if (NekoGui_sub::SubscriptionDownloader::fetch(request(path), id, result, error, nullptr, 100) ||
            error.isEmpty() || result.source != "ok") return 3;
    }
    std::atomic_bool cancelled{true};
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("ok"), id, result, error, &cancelled)) return 4;
    cancelled = false;
    QTimer::singleShot(50, &app, [&] { cancelled = true; });
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("hang"), id, result, error, &cancelled) ||
        !error.contains("cancelled") || result.source != "ok") return 5;
    return 0;
}
