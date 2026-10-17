#pragma once

#include "sub/ManagedProfileStore.hpp"
#include "sub/ManagedSession.hpp"
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QHostAddress>
#include <QProcess>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
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

class ManagedRealityCamouflageFixture : public QTcpServer {
public:
    QSslCertificate certificate;
    QSslKey key;

    void incomingConnection(qintptr descriptor) override {
        auto *socket = new QSslSocket(this);
        socket->setLocalCertificate(certificate);
        socket->setPrivateKey(key);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        if (!socket->setSocketDescriptor(descriptor)) { delete socket; return; }
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QSslSocket::readyRead, socket, [socket] { socket->readAll(); });
        socket->startServerEncryption();
    }
};

inline bool testManagedHttpsRefresh(const QString &certPath, const QString &keyPath,
                                    const std::shared_ptr<NekoGui::Group> &group,
                                    const std::function<bool()> &unchanged,
                                    const QString &realityServerExecutable = {},
                                    const QString &realityServerConfig = {},
                                    const QString &realityProfilePath = {}) {
    QFile certFile(certPath), keyFile(keyPath);
    if (!QSslSocket::supportsSsl() || !certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) return false;
    const auto certificateBytes = certFile.readAll();
    const auto keyBytes = keyFile.readAll();
    ManagedRefreshFixture server;
    server.certificate = QSslCertificate(certificateBytes);
    server.key = QSslKey(keyBytes, QSsl::Rsa);
    if (server.certificate.isNull() || server.key.isNull() || !server.listen(QHostAddress::LocalHost, 0)) return false;
    const auto originalSsl = QSslConfiguration::defaultConfiguration();
    struct RestoreTrust {
        QSslConfiguration configuration;
        ~RestoreTrust() { QSslConfiguration::setDefaultConfiguration(configuration); }
    } restore{originalSsl};
    auto trusted = originalSsl;
    trusted.setCaCertificates({server.certificate});
    QSslConfiguration::setDefaultConfiguration(trusted);
    QByteArray source =
        "# synthetic full document\n"
        "proxies:\n"
        "  - name: synthetic-reality\n"
        "    type: vless\n"
        "    server: 127.0.0.1\n"
        "    port: 443\n"
        "    uuid: 11111111-2222-4333-8444-555555555555\n"
        "    flow: xtls-rprx-vision\n"
        "    tls: true\n"
        "    network: tcp\n"
        "    servername: reality.test\n"
        "    client-fingerprint: chrome\n"
        "    reality-opts:\n"
        "      public-key: CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "      short-id: 01020304\n"
        "proxy-groups: [{name: select, type: select, proxies: [synthetic-reality]}]\n"
        "rules: ['MATCH,select']\n"
        "dns: {enable: true, nameserver: [127.0.0.1]}\n";
    QProcess realityServer;
    ManagedRealityCamouflageFixture camouflage;
    int realityServerPort = 0;
    int camouflagePort = 0;
    if (!realityProfilePath.isEmpty()) {
        QFile profileFile(realityProfilePath);
        if (!profileFile.open(QIODevice::ReadOnly) || realityServerExecutable.isEmpty() ||
            realityServerConfig.isEmpty()) return false;
        source = profileFile.readAll();
        if (source.isEmpty() || source.size() > 4 * 1024 * 1024) return false;
        if (!source.contains("    server: 127.0.0.1\n") ||
            !source.contains("    flow: xtls-rprx-vision\n") ||
            !source.contains("    tls: true\n") || !source.contains("    network: tcp\n") ||
            !source.contains("    servername: reality.test\n") ||
            !source.contains("    client-fingerprint: chrome\n") ||
            !source.contains("      public-key:") || !source.contains("      short-id:")) return false;
        static const QRegularExpression portExpression(QStringLiteral("(?:^|\\n)\\s*port:\\s*([0-9]{1,5})"));
        const auto portMatch = portExpression.match(QString::fromUtf8(source));
        if (!portMatch.hasMatch()) return false;
        realityServerPort = portMatch.captured(1).toInt();
        if (realityServerPort < 1 || realityServerPort > 65535) return false;
        QFile configFile(realityServerConfig);
        if (!configFile.open(QIODevice::ReadOnly)) return false;
        const auto config = QJsonDocument::fromJson(configFile.readAll()).object();
        const auto inbounds = config.value(QStringLiteral("inbounds")).toArray();
        if (inbounds.isEmpty()) return false;
        const auto inbound = inbounds.first().toObject();
        if (inbounds.size() != 1 || inbound.value(QStringLiteral("type")).toString() != QStringLiteral("vless")) return false;
        const auto tls = inbound.value(QStringLiteral("tls")).toObject();
        const auto reality = tls.value(QStringLiteral("reality")).toObject();
        const auto handshake = reality.value(QStringLiteral("handshake")).toObject();
        camouflagePort = handshake.value(QStringLiteral("server_port")).toInt();
        if (inbound.value(QStringLiteral("listen")).toString() != QStringLiteral("127.0.0.1") ||
            handshake.value(QStringLiteral("server")).toString() != QStringLiteral("127.0.0.1")) return false;
        camouflage.certificate = QSslCertificate(certificateBytes);
        camouflage.key = QSslKey(keyBytes, QSsl::Rsa);
        if (camouflagePort < 1 || camouflagePort > 65535 ||
            camouflage.certificate.isNull() || camouflage.key.isNull() ||
            !camouflage.listen(QHostAddress::LocalHost, quint16(camouflagePort))) return false;
    }
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
    NekoGui_sub::ManagedProfile expectedProfile;
    NekoGui_sub::SubscriptionMetadata metadata;
    QString error;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(source, expectedProfile, error)) return false;
    if (server.requests != 1 || !unchanged() || readBytes(group->fn) != groupBytes ||
        !store.loadSnapshot(group->id, profile, metadata, error) || profile.source != source ||
        profile.proxyNames != expectedProfile.proxyNames || profile.groupNames != expectedProfile.groupNames ||
        profile.rules != expectedProfile.rules ||
        !profile.source.contains("public-key:") || !profile.source.contains("short-id:") ||
        !profile.source.contains("flow: xtls-rprx-vision") ||
        !profile.source.contains("servername: reality.test") ||
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
    server.body.replace("type: vless", "type: deliberately-unsupported");
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
    const bool committed = server.requests == 4 && unchanged() && readBytes(group->fn) == groupBytes &&
        hwid(server.lastRequest) == firstId && readBytes(envelopePath + ".previous") == firstEnvelope &&
        store.loadSnapshot(group->id, profile, metadata, error) && profile.source == server.body &&
        profile.proxyNames == expectedProfile.proxyNames && profile.groupNames == expectedProfile.groupNames &&
        profile.rules == expectedProfile.rules && profile.source.contains("public-key:") &&
        profile.source.contains("short-id:") && profile.source.contains("flow: xtls-rprx-vision") &&
        profile.source.contains("servername: reality.test") && metadata.title == "Synthetic";
    if (committed && realityProfilePath.isEmpty())
        QTextStream(stdout) << "GROUPUPDATER_MANAGED_REALITY_REFRESH_SOURCE_PRESERVATION_PASS\n";
    if (!committed || realityProfilePath.isEmpty()) return committed;

    const auto realityDirectory = QFileInfo(realityServerConfig).absolutePath();
    realityServer.setWorkingDirectory(realityDirectory);
    realityServer.setStandardOutputFile(QProcess::nullDevice());
    realityServer.setStandardErrorFile(QProcess::nullDevice());
    realityServer.start(realityServerExecutable,
        {QStringLiteral("-D"), realityDirectory, QStringLiteral("run"), QStringLiteral("-c"),
         QFileInfo(realityServerConfig).absoluteFilePath()});
    if (!realityServer.waitForStarted(5000)) return false;
    struct StopRealityServer {
        QProcess &process;
        ~StopRealityServer() {
            if (process.state() != QProcess::NotRunning) {
                process.kill();
                process.waitForFinished(3000);
            }
        }
    } stopRealityServer{realityServer};
    bool realityReady = false;
    QElapsedTimer realityDeadline;
    realityDeadline.start();
    while (realityDeadline.elapsed() < 10000 && realityServer.state() != QProcess::NotRunning) {
        QTcpSocket probe;
        probe.connectToHost(QHostAddress::LocalHost, quint16(realityServerPort));
        if (probe.waitForConnected(100)) {
            probe.disconnectFromHost();
            realityReady = true;
            break;
        }
        QThread::msleep(50);
    }
    if (!realityReady) return false;

    QTcpServer origin;
    if (!origin.listen(QHostAddress::LocalHost, 0)) return false;
    int originRequests = 0;
    QObject::connect(&origin, &QTcpServer::newConnection, &origin, [&] {
        while (origin.hasPendingConnections()) {
            auto *socket = origin.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
                const auto request = socket->property("request").toByteArray() + socket->readAll();
                socket->setProperty("request", request);
                if (!request.contains("\r\n\r\n") || socket->property("replied").toBool()) return;
                socket->setProperty("replied", true);
                if (!request.startsWith("GET /managed-reality HTTP/1.1\r\n")) return;
                ++originRequests;
                socket->write("HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nmanaged-reality-pass");
                socket->disconnectFromHost();
            });
        }
    });
    NekoGui_sub::ManagedSession session;
    auto reservePort = [] {
        QTcpServer reservation;
        if (!reservation.listen(QHostAddress::LocalHost, 0)) return 0;
        return int(reservation.serverPort());
    };
    const int mixedPort = reservePort();
    const int controllerPort = reservePort();
    if (mixedPort == 0 || controllerPort == 0 || mixedPort == controllerPort) return false;
    if (!session.start(store, group->id,
            QCoreApplication::applicationDirPath() + QStringLiteral("/mihomo.exe"),
            mixedPort, controllerPort, 10000, error)) {
        QTextStream(stderr) << "GROUPUPDATER_MANAGED_REALITY_SESSION_START_FAILED: " << error << "\n";
        return false;
    }
    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, quint16(mixedPort));
    if (!client.waitForConnected(1000)) {
        session.stop(error);
        return false;
    }
    const auto originTarget = QByteArray("127.0.0.1:") + QByteArray::number(origin.serverPort());
    const auto request = QByteArray("GET http://") + originTarget +
        "/managed-reality HTTP/1.1\r\nHost: " + originTarget + "\r\nConnection: close\r\n\r\n";
    if (client.write(request) != request.size()) {
        session.stop(error);
        return false;
    }
    QByteArray response;
    QEventLoop responseLoop;
    QTimer responseDeadline;
    responseDeadline.setSingleShot(true);
    QObject::connect(&client, &QTcpSocket::readyRead, &responseLoop, [&] { response += client.readAll(); });
    QObject::connect(&client, &QTcpSocket::disconnected, &responseLoop, &QEventLoop::quit);
    QObject::connect(&responseDeadline, &QTimer::timeout, &responseLoop, [&] {
        client.abort();
        responseLoop.quit();
    });
    responseDeadline.start(8000);
    if (client.state() != QAbstractSocket::UnconnectedState) responseLoop.exec();
    response += client.readAll();
    const auto bodyOffset = response.indexOf("\r\n\r\n");
    const bool dataPathPassed = bodyOffset >= 0 && response.startsWith("HTTP/1.1 200") &&
        response.mid(bodyOffset + 4) == "managed-reality-pass" && originRequests == 1;
    const bool stopped = session.stop(error);
    QTcpSocket mixedAfter, controllerAfter;
    mixedAfter.connectToHost(QHostAddress::LocalHost, quint16(mixedPort));
    controllerAfter.connectToHost(QHostAddress::LocalHost, quint16(controllerPort));
    if (!dataPathPassed || !stopped || mixedAfter.waitForConnected(500) || controllerAfter.waitForConnected(500)) {
        QTextStream(stderr) << "GROUPUPDATER_MANAGED_REALITY_DATA_PATH_FAILED requests=" << originRequests << "\n";
        return false;
    }
    realityServer.terminate();
    if (!realityServer.waitForFinished(1500)) {
        realityServer.kill();
        if (!realityServer.waitForFinished(3000)) return false;
    }
    QTextStream(stdout) << "GROUPUPDATER_MANAGED_REALITY_REFRESH_TO_SESSION_LOOPBACK_DATA_PATH_PASS requests=1\n";
    return true;
}
