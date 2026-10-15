#include "../../sub/ManagedRuntimePolicy.hpp"
#include "../../sub/MihomoValidator.hpp"
#include "../../sub/ManagedCoreProcess.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QProcess>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextStream>
#include <QTimer>
#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
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
    NekoGui_sub::ManagedCoreProcess child;
    if (child.start(executable + ".missing", panel, mixedPort, apiPort, token, error) ||
        child.processId() != 0 || child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed) return 18;
    mixedReservation.close();
    apiReservation.close();
    if (!child.start(executable, panel, mixedPort, apiPort, token, error)) return 6;
    const auto ownedPid = child.processId();
    if (!ownedPid || child.state() != NekoGui_sub::ManagedCoreProcess::State::Running ||
        child.start(executable, panel, mixedPort, apiPort, token, error) || child.processId() != ownedPid) return 7;
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
    QByteArray body;
    if (child.waitReady(0, error) || child.processId() != ownedPid ||
        child.state() != NekoGui_sub::ManagedCoreProcess::State::Running) return 22;
    if (!child.waitReady(10000, error) || child.state() != NekoGui_sub::ManagedCoreProcess::State::Ready ||
        !child.waitReady(1000, error)) return 8;
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
    const auto signal = [&](qint64 pid) {
        bool signalSent = false;
#ifdef Q_OS_WIN
        QProcess helper;
        helper.start(QCoreApplication::applicationDirPath() + "/mdmbox_test_console_break.exe",
                     {QString::number(pid)});
        if (helper.waitForStarted(2000)) {
            if (!helper.waitForFinished(3000)) { helper.kill(); helper.waitForFinished(1000); }
            signalSent = helper.exitStatus() == QProcess::NormalExit && helper.exitCode() == 0;
        }
#else
    Q_UNUSED(pid)
#endif
        return signalSent;
    };
    if (!child.stop(signal, error) || child.state() != NekoGui_sub::ManagedCoreProcess::State::Stopped ||
        child.processId() != 0 || !child.stop(signal, error)) return 11;
    QTcpSocket apiAfter, mixedAfter;
    apiAfter.connectToHost(QHostAddress::LocalHost, apiPort);
    mixedAfter.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (apiAfter.waitForConnected(500) || mixedAfter.waitForConnected(500)) return 12;
    QTextStream(stdout) << "MIHOMO_RUNTIME_API_AUTH_LISTENER_STOP_PASS forced=0\n";
    QTextStream(stdout) << "MIHOMO_CONSOLE_GRACEFUL_EXIT_PASS code=0\n";
    if (!child.start(executable, panel, mixedPort, apiPort, token, error)) return 19;
    if (!child.waitReady(10000, error) || child.stop({}, error) || error.isEmpty() || child.processId() != 0 ||
        child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed) return 20;
    QTcpSocket forcedApiAfter, forcedMixedAfter;
    forcedApiAfter.connectToHost(QHostAddress::LocalHost, apiPort);
    forcedMixedAfter.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (forcedApiAfter.waitForConnected(500) || forcedMixedAfter.waitForConnected(500)) return 21;
    QTextStream(stdout) << "MIHOMO_PROCESS_OWNERSHIP_FAILURE_CLEANUP_PASS\n";
    if (child.waitReady(1000, error) || child.processId() != 0) return 23;
    QTcpServer blockedApi;
    if (!blockedApi.listen(QHostAddress::LocalHost, apiPort)) return 24;
    QObject::connect(&blockedApi, &QTcpServer::newConnection, &app, [&] {
        while (blockedApi.hasPendingConnections()) {
            auto *socket = blockedApi.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket] {
                socket->readAll();
                socket->write("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                socket->disconnectFromHost();
            });
        }
    });
    // A foreign listener must not be mistaken for a ready owned core.
    if (!child.start(executable, panel, mixedPort, apiPort, token, error)) return 25;
    if (child.waitReady(1000, error) || child.processId() != 0 || error.isEmpty() ||
        child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed) return 26;
    blockedApi.close();
    QTextStream(stdout) << "MIHOMO_AUTHENTICATED_READINESS_FAILURE_PASS\n";
#ifdef Q_OS_WIN
    const auto portsClosed = [&] {
        QTcpSocket api, mixedSocket;
        api.connectToHost(QHostAddress::LocalHost, apiPort);
        mixedSocket.connectToHost(QHostAddress::LocalHost, mixedPort);
        return !api.waitForConnected(500) && !mixedSocket.waitForConnected(500);
    };
    if (!child.start(executable, panel, mixedPort, apiPort, token, error) || !child.waitReady(10000, error)) return 27;
    // Hold a kernel handle, not just a PID: never terminate a recycled process ID.
    HANDLE crashed = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(child.processId()));
    if (!crashed) return 28;
    const bool killed = TerminateProcess(crashed, 42) && WaitForSingleObject(crashed, 3000) == WAIT_OBJECT_0;
    CloseHandle(crashed);
    if (!killed) return 29;
    QElapsedTimer observed;
    observed.start();
    while (child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed && observed.elapsed() < 3000) {
        QEventLoop pause;
        QTimer::singleShot(20, &pause, &QEventLoop::quit);
        pause.exec();
    }
    if (child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed || child.waitReady(1000, error) ||
        child.stop(signal, error) || error.isEmpty() || child.processId() != 0 || !portsClosed()) return 30;
    QTextStream(stdout) << "MIHOMO_UNEXPECTED_EXIT_STATE_PASS\n";
    HANDLE owned = nullptr;
    {
        NekoGui_sub::ManagedCoreProcess scoped;
        if (!scoped.start(executable, panel, mixedPort, apiPort, token, error) || !scoped.waitReady(10000, error)) return 31;
        owned = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(scoped.processId()));
        if (!owned) return 32;
    } // Destructor must reap the owned core even without an explicit stop.
    const bool reaped = WaitForSingleObject(owned, 3000) == WAIT_OBJECT_0;
    CloseHandle(owned);
    if (!reaped || !portsClosed()) return 33;
    QTextStream(stdout) << "MIHOMO_DESTRUCTOR_CHILD_CLEANUP_PASS\n";
#endif
    return 0;
}
