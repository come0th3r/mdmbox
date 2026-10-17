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
                else if (input.startsWith("GET /status-401 ")) response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-403 ")) response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-404 ")) response = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-429 ")) response = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-500 ")) response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-502 ")) response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-503 ")) response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\n\r\nno";
                else if (input.startsWith("GET /status-504 ")) response = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 2\r\n\r\nno";
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
    for (const auto &path : {"redirect", "large", "empty", "badmeta", "hang"}) {
        if (NekoGui_sub::SubscriptionDownloader::fetch(request(path), id, result, error, nullptr, 100) ||
            error.isEmpty() || result.source != "ok") return 3;
    }
    for (const auto &status : {401, 403, 404, 429, 500, 502, 503, 504}) {
        NekoGui_sub::SubscriptionFetchDiagnostics diagnostics;
        const auto path = QStringLiteral("status-%1").arg(status);
        if (NekoGui_sub::SubscriptionDownloader::fetch(request(path), id, result, error,
                                                        nullptr, 100, &diagnostics) ||
            error.isEmpty() || result.source != "ok" || diagnostics.httpStatus != status ||
            diagnostics.networkError == 0 || diagnostics.tlsError || diagnostics.responseBytes != 2) return 6;
    }
    std::atomic_bool cancelled{true};
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("ok"), id, result, error, &cancelled)) return 4;
    cancelled = false;
    QTimer::singleShot(50, &app, [&] { cancelled = true; });
    if (NekoGui_sub::SubscriptionDownloader::fetch(request("hang"), id, result, error, &cancelled) ||
        !error.contains("cancelled") || result.source != "ok") return 5;
    return 0;
}
