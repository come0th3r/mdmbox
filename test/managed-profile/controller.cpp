#include "../../sub/ManagedControllerProbe.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextStream>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    using Probe = NekoGui_sub::ManagedControllerProbe;
    const QByteArray token(64, 'a');
    int requests = 0;
    bool headersValid = true;
    QByteArray response;
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) return 1;
    QObject::connect(&server, &QTcpServer::newConnection, &app, [&] {
        while (server.hasPendingConnections()) {
            auto *socket = server.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
                auto input = socket->property("input").toByteArray() + socket->readAll();
                socket->setProperty("input", input);
                if (!input.contains("\r\n\r\n") || socket->property("sent").toBool()) return;
                socket->setProperty("sent", true);
                ++requests;
                headersValid &= input.startsWith("GET /version HTTP/1.1\r\n") &&
                    input.contains("Authorization: Bearer " + token + "\r\n");
                if (response.isEmpty()) return; // Stall until bounded request aborts.
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });
    const auto run = [&](const QByteArray &status, const QByteArray &body, Probe::Result expected) {
        response = "HTTP/1.1 " + status + "\r\nContent-Length: " + QByteArray::number(body.size()) +
            "\r\nConnection: close\r\n\r\n" + body;
        return Probe::version(server.serverPort(), token, 500) == expected;
    };
    if (!run("200 OK", "{\"version\":\"v1.19.32\"}", Probe::Result::Accepted)) return 2;
    if (!run("200 OK", "{\"version\":\"v1.19.320\"}", Probe::Result::Rejected)) return 3;
    if (!run("200 OK", "not JSON", Probe::Result::Rejected)) return 4;
    if (!run("200 OK", "[]", Probe::Result::Rejected)) return 5;
    if (!run("401 Unauthorized", "", Probe::Result::Rejected)) return 6;
    if (!run("200 OK", QByteArray(8192, 'x'), Probe::Result::Rejected)) return 7;
    const auto beforeRedirect = requests;
    response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:" + QByteArray::number(server.serverPort()) +
        "/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    if (Probe::version(server.serverPort(), token, 500) != Probe::Result::Rejected || requests != beforeRedirect + 1) return 8;
    response.clear();
    QElapsedTimer elapsed;
    elapsed.start();
    if (Probe::version(server.serverPort(), token, 100) != Probe::Result::Retry || elapsed.elapsed() > 2000) return 9;
    const auto beforeInvalid = requests;
    if (Probe::version(server.serverPort(), "bad\r\n", 500) != Probe::Result::Rejected ||
        Probe::version(server.serverPort(), token, 0) != Probe::Result::Rejected || requests != beforeInvalid) return 10;
    if (!headersValid || requests != 8) return 11;
    QTextStream(stdout) << "CONTROLLER_PROBE_NEGATIVE_FIXTURES_PASS requests=8\n";
    return 0;
}
