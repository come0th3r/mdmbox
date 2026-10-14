#include "../../sub/ManagedRuntimePolicy.hpp"
#include "../../sub/MihomoValidator.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTextStream>
#include <QTimer>

struct ChildGuard {
    QProcess process;
    ~ChildGuard() {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished(3000);
        }
    }
};

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    if (app.arguments().size() != 2) return 1;
    const auto executable = app.arguments()[1];
    QString error;
    if (!NekoGui_sub::MihomoValidator::verifyExecutable(executable, error)) return 2;
    // Reserve distinct ports until immediately before start; bind race remains possible.
    QTcpServer mixedReservation, apiReservation;
    if (!mixedReservation.listen(QHostAddress::LocalHost, 0) || !apiReservation.listen(QHostAddress::LocalHost, 0)) return 3;
    const auto mixedPort = mixedReservation.serverPort();
    const auto apiPort = apiReservation.serverPort();
    QByteArray token;
    for (int i = 0; i < 8; ++i) token += QByteArray::number(QRandomGenerator::system()->generate(), 16).rightJustified(8, '0');
    const QByteArray source =
        "proxies: [{name: unused, type: socks5, server: 127.0.0.1, port: 1}]\n"
        "proxy-groups: [{name: select, type: select, proxies: [unused, DIRECT]}]\n"
        "rules: ['MATCH,DIRECT']\ndns: {enable: false, nameserver: [127.0.0.1]}\n";
    NekoGui_sub::ManagedProfile panel, projected;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(source, panel, error) ||
        !NekoGui_sub::ManagedRuntimePolicy::projectLoopback(panel, mixedPort, apiPort, token, projected, error) ||
        !NekoGui_sub::MihomoValidator::validate(executable, projected, error)) return 4;
    QTemporaryDir home;
    if (!home.isValid()) return 5;
    ChildGuard child;
    auto env = QProcessEnvironment::systemEnvironment();
    for (const auto &key : env.keys()) if (key.startsWith("CLASH_", Qt::CaseInsensitive)) env.remove(key);
    child.process.setProcessEnvironment(env);
    child.process.setWorkingDirectory(home.path());
    child.process.setStandardOutputFile(QProcess::nullDevice());
    child.process.setStandardErrorFile(QProcess::nullDevice());
    mixedReservation.close();
    apiReservation.close();
    child.process.start(executable, {"-d", home.path(), "-f", "-"});
    if (!child.process.waitForStarted(5000)) return 6;
    if (child.process.write(projected.source) != projected.source.size()) return 7;
    child.process.closeWriteChannel();
    QNetworkAccessManager manager;
    manager.setProxy(QNetworkProxy::NoProxy);
    auto get = [&](bool authorized, QByteArray &body) {
        QNetworkRequest request(QUrl(QString("http://127.0.0.1:%1/version").arg(apiPort)));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        if (authorized) request.setRawHeader("Authorization", "Bearer " + token);
        auto *reply = manager.get(request);
        reply->setReadBufferSize(8192);
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timeout.start(500);
        if (!reply->isFinished()) loop.exec();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        body = reply->isOpen() ? reply->read(8192) : QByteArray{};
        delete reply;
        return status;
    };
    QElapsedTimer deadline;
    deadline.start();
    QByteArray body;
    bool ready = false;
    while (deadline.elapsed() < 10000 && child.process.state() != QProcess::NotRunning) {
        if (get(true, body) == 200) { ready = true; break; }
        QEventLoop pause;
        QTimer::singleShot(50, &pause, &QEventLoop::quit);
        pause.exec();
    }
    if (!ready || !QJsonDocument::fromJson(body).object().value("version").toString().contains("1.19.32")) return 8;
    if (get(false, body) != 401 || get(true, body) != 200) return 9;
    QTcpSocket mixed;
    mixed.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (!mixed.waitForConnected(1000)) return 10;
    mixed.disconnectFromHost();
    QTcpServer origin;
    if (!origin.listen(QHostAddress::LocalHost, 0)) return 13;
    int originRequests = 0;
    bool validOriginRequest = false;
    QObject::connect(&origin, &QTcpServer::newConnection, &app, [&] {
        while (origin.hasPendingConnections()) {
            auto *socket = origin.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
                const auto input = socket->property("input").toByteArray() + socket->readAll();
                socket->setProperty("input", input);
                if (!input.contains("\r\n\r\n") || socket->property("sent").toBool()) return;
                socket->setProperty("sent", true);
                ++originRequests;
                validOriginRequest = input.startsWith("GET /managed-smoke HTTP/1.1\r\n");
                socket->write("HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nmanaged-path-pass");
                socket->disconnectFromHost();
            });
        }
    });
    // Raw absolute-form HTTP request forces traversal through the mixed listener,
    // avoiding any HTTP client's implicit bypass for loopback destinations.
    QTcpSocket proxyClient;
    proxyClient.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (!proxyClient.waitForConnected(1000)) return 14;
    const auto originAddress = QByteArray("127.0.0.1:") + QByteArray::number(origin.serverPort());
    const auto proxyRequest = "GET http://" + originAddress + "/managed-smoke HTTP/1.1\r\nHost: " +
        originAddress + "\r\nConnection: close\r\n\r\n";
    QEventLoop transferLoop;
    QTimer transferDeadline;
    QByteArray response;
    bool oversized = false;
    bool timedOut = false;
    auto collect = [&] {
        response += proxyClient.read(8193 - response.size());
        if (response.size() > 8192) { oversized = true; proxyClient.abort(); transferLoop.quit(); }
    };
    QObject::connect(&proxyClient, &QTcpSocket::readyRead, &transferLoop, collect);
    QObject::connect(&proxyClient, &QTcpSocket::disconnected, &transferLoop, &QEventLoop::quit);
    transferDeadline.setSingleShot(true);
    QObject::connect(&transferDeadline, &QTimer::timeout, &transferLoop, [&] {
        timedOut = true;
        proxyClient.abort();
        transferLoop.quit();
    });
    transferDeadline.start(5000);
    if (proxyClient.write(proxyRequest) != proxyRequest.size()) return 15;
    if (proxyClient.state() != QAbstractSocket::UnconnectedState) transferLoop.exec();
    transferDeadline.stop();
    if (proxyClient.bytesAvailable() > 0) collect();
    const auto headerEnd = response.indexOf("\r\n\r\n");
    if (timedOut || oversized || originRequests != 1 || !validOriginRequest ||
        !response.startsWith("HTTP/1.1 200") || headerEnd < 0 ||
        response.mid(headerEnd + 4) != "managed-path-pass") return 16;
    QTextStream(stdout) << "MIHOMO_LOOPBACK_HTTP_DATA_PATH_PASS requests=1\n";
    // QProcess::terminate on Windows is not proof of graceful console shutdown.
    child.process.terminate();
    const bool terminated = child.process.waitForFinished(2000);
    if (!terminated) {
        child.process.kill();
        if (!child.process.waitForFinished(3000)) return 11;
    }
    QTcpSocket apiAfter, mixedAfter;
    apiAfter.connectToHost(QHostAddress::LocalHost, apiPort);
    mixedAfter.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (apiAfter.waitForConnected(500) || mixedAfter.waitForConnected(500)) return 12;
    QTextStream(stdout) << "MIHOMO_RUNTIME_API_AUTH_LISTENER_STOP_PASS forced=" << (!terminated ? 1 : 0) << "\n";
    return 0;
}
