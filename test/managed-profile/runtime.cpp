#include "../../sub/ManagedRuntimePolicy.hpp"
#include "../../sub/MihomoValidator.hpp"
#include "../../sub/ManagedCoreProcess.hpp"
#include "../../sub/CoreOwnership.hpp"
#include "../../sub/ManagedSession.hpp"
#include "../../sub/ManagedSessionController.hpp"
#include <QDateTime>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QProcess>
#include <QRandomGenerator>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTextStream>
#include <QTimer>
#include <yaml-cpp/yaml.h>
#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

class LoopbackTlsOrigin final : public QTcpServer {
public:
    QSslCertificate certificate;
    QSslKey privateKey;
    int requests = 0;

    void incomingConnection(qintptr descriptor) override {
        auto *socket = new QSslSocket(this);
        socket->setLocalCertificate(certificate);
        socket->setPrivateKey(privateKey);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        if (!socket->setSocketDescriptor(descriptor)) {
            delete socket;
            return;
        }
        QObject::connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        QObject::connect(socket, &QSslSocket::encrypted, socket, [this, socket] {
            QObject::connect(socket, &QSslSocket::readyRead, socket, [this, socket] {
                const auto input = socket->property("tls-origin-input").toByteArray() + socket->readAll();
                socket->setProperty("tls-origin-input", input);
                if (!input.contains("\r\n\r\n") || socket->property("tls-origin-sent").toBool()) return;
                socket->setProperty("tls-origin-sent", true);
                if (input.startsWith("GET /managed-tls HTTP/1.1\r\n")) ++requests;
                const QByteArray body("managed-tls-path-pass");
                socket->write("HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(body.size()) +
                              "\r\nConnection: close\r\n\r\n" + body);
                socket->disconnectFromHost();
            });
        });
        QObject::connect(socket, &QSslSocket::sslErrors, socket,
            [socket](const QList<QSslError> &) { socket->disconnectFromHost(); });
        socket->startServerEncryption();
    }
};

class LoopbackSocks5UdpEndpoint final : public QObject {
public:
    QTcpServer controlServer;
    QUdpSocket relaySocket;
    QUdpSocket originSocket;
    int associations = 0;
    int relayedDatagrams = 0;
    int originDatagrams = 0;

    bool start(QString &error) {
        if (!originSocket.bind(QHostAddress::LocalHost, 0) ||
            !relaySocket.bind(QHostAddress::LocalHost, 0) ||
            !controlServer.listen(QHostAddress::LocalHost, 0)) {
            error = QStringLiteral("Unable to bind SOCKS5 UDP fixture sockets");
            return false;
        }
        QObject::connect(&controlServer, &QTcpServer::newConnection, this, [this] {
            while (controlServer.hasPendingConnections()) {
                auto *client = controlServer.nextPendingConnection();
                auto *buffer = new QByteArray;
                auto *stage = new int(0);
                QObject::connect(client, &QTcpSocket::disconnected, client, &QObject::deleteLater);
                QObject::connect(client, &QObject::destroyed, [buffer, stage] { delete buffer; delete stage; });
                QObject::connect(client, &QTcpSocket::readyRead, client, [this, client, buffer, stage] {
                    *buffer += client->readAll();
                    if (*stage == 0 && buffer->size() >= 2) {
                        const auto count = static_cast<quint8>((*buffer)[1]);
                        if (static_cast<quint8>((*buffer)[0]) != 5 || count == 0 || buffer->size() < 2 + count) {
                            if (buffer->size() >= 2 + count) client->disconnectFromHost();
                            return;
                        }
                        bool noAuthOffered = false;
                        for (int i = 0; i < count; ++i)
                            noAuthOffered = noAuthOffered || static_cast<quint8>((*buffer)[2 + i]) == 0;
                        if (!noAuthOffered) {
                            client->write(QByteArray::fromHex("05ff"));
                            client->disconnectFromHost();
                            return;
                        }
                        *buffer = buffer->mid(2 + count);
                        *stage = 1;
                        client->write(QByteArray::fromHex("0500"));
                    }
                    if (*stage == 1 && buffer->size() >= 10) {
                        const auto request = *buffer;
                        *buffer = buffer->mid(10);
                        if (static_cast<quint8>(request[0]) != 5 || static_cast<quint8>(request[1]) != 3 ||
                            static_cast<quint8>(request[2]) != 0 || static_cast<quint8>(request[3]) != 1) {
                            client->write(QByteArray::fromHex("05070001000000000000"));
                            client->disconnectFromHost();
                            return;
                        }
                        const auto port = relaySocket.localPort();
                        QByteArray response = QByteArray::fromHex("050000017f000001") +
                            QByteArray(1, char((port >> 8) & 0xff)) + QByteArray(1, char(port & 0xff));
                        ++associations;
                        *stage = 2;
                        client->write(response);
                    }
                });
            }
        });
        QObject::connect(&relaySocket, &QUdpSocket::readyRead, this, [this] {
            while (relaySocket.hasPendingDatagrams()) {
                QByteArray packet(int(relaySocket.pendingDatagramSize()), Qt::Uninitialized);
                QHostAddress sender;
                quint16 senderPort = 0;
                const auto length = relaySocket.readDatagram(packet.data(), packet.size(), &sender, &senderPort);
                if (length < 0) continue;
                packet.resize(int(length));
                if (sender == QHostAddress::LocalHost && senderPort == originSocket.localPort()) {
                    if (packet.size() < 10 || lastClientPort == 0) continue;
                    QByteArray response = QByteArray::fromHex("000000017f000001") +
                        QByteArray(1, char((originSocket.localPort() >> 8) & 0xff)) +
                        QByteArray(1, char(originSocket.localPort() & 0xff)) + packet;
                    relaySocket.writeDatagram(response, lastClientAddress, lastClientPort);
                    continue;
                }
                if (packet.size() < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 ||
                    static_cast<quint8>(packet[3]) != 1 || packet.mid(4, 4) != QByteArray::fromHex("7f000001"))
                    continue;
                const auto destinationPort = (static_cast<quint8>(packet[8]) << 8) | static_cast<quint8>(packet[9]);
                if (destinationPort != originSocket.localPort()) continue;
                lastClientAddress = sender;
                lastClientPort = senderPort;
                ++relayedDatagrams;
                relaySocket.writeDatagram(packet.mid(10), QHostAddress::LocalHost, originSocket.localPort());
            }
        });
        QObject::connect(&originSocket, &QUdpSocket::readyRead, this, [this] {
            while (originSocket.hasPendingDatagrams()) {
                QByteArray request(int(originSocket.pendingDatagramSize()), Qt::Uninitialized);
                QHostAddress sender;
                quint16 senderPort = 0;
                const auto length = originSocket.readDatagram(request.data(), request.size(), &sender, &senderPort);
                if (length < 0) continue;
                request.resize(int(length));
                if (request != QByteArray("synthetic-udp-request")) continue;
                ++originDatagrams;
                originSocket.writeDatagram("managed-udp-pass", sender, senderPort);
            }
        });
        error.clear();
        return true;
    }

private:
    QHostAddress lastClientAddress;
    quint16 lastClientPort = 0;
};

static int runRealityProfileFixture(const QString &executable, const QString &profilePath) {
    QString error;
    QFile sourceFile(profilePath);
    if (!sourceFile.open(QIODevice::ReadOnly)) return 150;
    const auto source = sourceFile.readAll();
    NekoGui_sub::ManagedProfile panel;
    if (!NekoGui_sub::ManagedProfile::ParseMihomo(source, panel, error)) {
        QTextStream(stderr) << "REALITY_PROFILE_PARSE_FAILED: " << error << "\n";
        return 151;
    }
    if (panel.proxyNames != QStringList{"synthetic-reality"} ||
        !NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(panel, error)) {
        QTextStream(stderr) << "REALITY_PROFILE_POLICY_REJECTED: " << error << "\n";
        return 152;
    }
    QTextStream(stdout) << "VLESS_REALITY_PRODUCTION_PROFILE_PARSE_AND_POLICY_PASS\n";
    auto freePort = []() -> quint16 {
        QTcpServer reservation;
        if (!reservation.listen(QHostAddress::LocalHost, 0)) return 0;
        const auto port = reservation.serverPort();
        reservation.close();
        return port;
    };
    const auto mixedPort = freePort();
    const auto apiPort = freePort();
    if (!mixedPort || !apiPort || mixedPort == apiPort) return 153;
    NekoGui_sub::ManagedProfile projected;
    if (!NekoGui_sub::ManagedRuntimePolicy::projectLoopback(panel, mixedPort, apiPort,
            QByteArray(64, 'c'), projected, error) ||
        !NekoGui_sub::MihomoValidator::validate(executable, projected, error)) {
        QTextStream(stderr) << "REALITY_PROFILE_PINNED_CORE_VALIDATION_FAILED: " << error << "\n";
        return 154;
    }
    QTextStream(stdout) << "VLESS_REALITY_PRODUCTION_PROFILE_PINNED_CORE_CONFIG_CHECK_PASS\n";
    QTcpServer origin;
    if (!origin.listen(QHostAddress::LocalHost, 0)) return 155;
    int originRequests = 0;
    bool validRequest = false;
    QObject::connect(&origin, &QTcpServer::newConnection, &origin, [&] {
        while (origin.hasPendingConnections()) {
            auto *socket = origin.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
                const auto input = socket->property("reality-profile-input").toByteArray() + socket->readAll();
                socket->setProperty("reality-profile-input", input);
                if (!input.contains("\r\n\r\n") || socket->property("reality-profile-replied").toBool()) return;
                const auto requestLineEnd = input.indexOf("\r\n");
                const auto headersEnd = input.indexOf("\r\n\r\n");
                const auto headers = headersEnd >= 0 ? input.mid(requestLineEnd + 2, headersEnd - requestLineEnd - 2)
                                                     : QByteArray{};
                const auto lengthMarker = headers.toLower().indexOf("content-length:");
                if (lengthMarker >= 0) {
                    const auto valueStart = lengthMarker + int(sizeof("content-length:") - 1);
                    const auto valueEnd = headers.indexOf("\r\n", valueStart);
                    const auto contentLength = headers.mid(valueStart, valueEnd < 0 ? -1 : valueEnd - valueStart)
                                                   .trimmed().toInt();
                    if (contentLength > 0 && input.size() < headersEnd + 4 + contentLength) return;
                }
                socket->setProperty("reality-profile-replied", true);
                ++originRequests;
                validRequest = requestLineEnd > 0 && input.left(requestLineEnd) == "GET /managed-reality HTTP/1.1";
                socket->write("HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nmanaged-reality-pass");
                socket->disconnectFromHost();
            });
        }
    });
    QTemporaryDir home;
    if (!home.isValid()) return 156;
    NekoGui_sub::ManagedProfileStore store(home.filePath(QStringLiteral("snapshots")));
    const auto validate = [&](const NekoGui_sub::ManagedProfile &candidate, QString &reason) {
        NekoGui_sub::ManagedProfile candidateProjection;
        return NekoGui_sub::ManagedRuntimePolicy::projectLoopback(candidate, mixedPort, apiPort,
                   QByteArray(64, 'c'), candidateProjection, reason) &&
               NekoGui_sub::MihomoValidator::validate(executable, candidateProjection, reason);
    };
    if (!store.commit(1, source, validate, error)) {
        QTextStream(stderr) << "REALITY_PROFILE_PRODUCTION_STORE_COMMIT_FAILED: " << error << "\n";
        return 157;
    }
    NekoGui_sub::ManagedSession session;
    if (!session.start(store, 1, executable, mixedPort, apiPort, 10000, error)) {
        QTextStream(stderr) << "REALITY_PROFILE_PRODUCTION_SESSION_START_FAILED: " << error << "\n";
        return 158;
    }
    QTextStream(stdout) << "VLESS_REALITY_PRODUCTION_PROFILE_STORE_AND_READY_PASS\n";
    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (!client.waitForConnected(1000)) {
        session.stop(error);
        return 159;
    }
    const auto target = QByteArray("127.0.0.1:") + QByteArray::number(origin.serverPort());
    const auto request = QByteArray("GET http://") + target +
        "/managed-reality HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n";
    if (client.write(request) != request.size()) {
        session.stop(error);
        return 160;
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
    const bool pathPassed = bodyOffset >= 0 && response.startsWith("HTTP/1.1 200") &&
        response.mid(bodyOffset + 4) == "managed-reality-pass" && originRequests == 1 && validRequest;
    const auto stopped = session.stop(error);
    QTcpSocket apiAfter, mixedAfter;
    apiAfter.connectToHost(QHostAddress::LocalHost, apiPort);
    mixedAfter.connectToHost(QHostAddress::LocalHost, mixedPort);
    if (!pathPassed || !stopped || apiAfter.waitForConnected(500) || mixedAfter.waitForConnected(500)) {
        QTextStream(stderr) << "REALITY_PROFILE_LOOPBACK_PATH_FAILED requests=" << originRequests << "\n";
        return 161;
    }
    QTextStream(stdout) << "VLESS_REALITY_PRODUCTION_PROFILE_LOOPBACK_TCP_DATA_PATH_PASS requests=1\n";
    return 0;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const bool rulesOnly = app.arguments().size() == 3 && app.arguments()[2] == QStringLiteral("--rules-only");
    const bool realityProfile = app.arguments().size() == 4 && app.arguments()[2] == QStringLiteral("--reality-profile");
    if ((rulesOnly && app.arguments().size() != 3) ||
        (realityProfile && app.arguments().size() != 4) ||
        (!rulesOnly && !realityProfile && app.arguments().size() != 4)) return 1;
    const auto executable = app.arguments()[1];
    const auto certificatePath = rulesOnly || realityProfile ? QString{} : app.arguments()[2];
    const auto privateKeyPath = rulesOnly || realityProfile ? QString{} : app.arguments()[3];
    QString error;
    if (!realityProfile && !NekoGui_sub::MihomoValidator::verifyExecutable(executable, error)) return 2;
    if (realityProfile) {
        const auto result = runRealityProfileFixture(executable, app.arguments()[3]);
        if (NekoGui_sub::CoreOwnership::shared().owner() != NekoGui_sub::CoreOwnership::Owner::None) {
            QTextStream(stderr) << "REALITY_PROFILE_FIXTURE_CORE_OWNERSHIP_LEAK\n";
            return 162;
        }
        return result;
    }
    // Exercise panel rule order, common matcher families, explicit terminal
    // actions, and custom selector targets against the pinned core before any
    // runtime process is started. Everything is synthetic and self-contained.
    {
        const QByteArray rulesProfile =
            "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 1}]\n"
            "proxy-groups:\n"
            "  - {name: all, type: select, proxies: [node, DIRECT]}\n"
            "  - {name: ru_direct, type: select, proxies: [DIRECT]}\n"
            "  - {name: blocked, type: select, proxies: [REJECT]}\n"
            "rules:\n"
            "  - 'DOMAIN,example.invalid,all'\n"
            "  - 'DOMAIN-SUFFIX,private.invalid,ru_direct'\n"
            "  - 'IP-CIDR,192.0.2.0/24,blocked,no-resolve'\n"
            "  - 'SRC-IP-CIDR,198.51.100.7/32,DIRECT'\n"
            "  - 'DST-PORT,443,REJECT'\n"
            "  - 'NETWORK,UDP,REJECT-DROP'\n"
            "  - 'MATCH,all'\n"
            "dns: {enable: false, nameserver: [127.0.0.1]}\n";
        const QStringList expectedRules{
            "DOMAIN,example.invalid,all", "DOMAIN-SUFFIX,private.invalid,ru_direct",
            "IP-CIDR,192.0.2.0/24,blocked,no-resolve", "SRC-IP-CIDR,198.51.100.7/32,DIRECT",
            "DST-PORT,443,REJECT", "NETWORK,UDP,REJECT-DROP", "MATCH,all"};
        NekoGui_sub::ManagedRuntimeRuleOverrides overrides;
        overrides.technicalRules = {"IP-CIDR,127.0.0.1/32,DIRECT,no-resolve"};
        overrides.localRules = {"DOMAIN-SUFFIX,local.example,blocked"};
        NekoGui_sub::ManagedProfile panel, projected;
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(rulesProfile, panel, error) ||
            panel.rules != expectedRules || panel.groupNames != QStringList{"all", "ru_direct", "blocked"} ||
            !NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(panel, error)) {
            QTextStream(stderr) << "MANAGED_RULE_MATRIX_CONFIG_REJECTED\n";
            return 1001;
        }
        QTextStream(stdout) << "MANAGED_RULE_MATRIX_PARSE_AND_RESOURCE_POLICY_PASS" << Qt::endl;
        QStringList layeredRules = overrides.technicalRules + overrides.localRules + expectedRules;
        if (!NekoGui_sub::ManagedRuntimePolicy::projectLoopback(panel, 17891, 17892,
                QByteArray(64, 'b'), overrides, projected, error) || projected.rules != layeredRules ||
            projected.groupNames != panel.groupNames) {
            QTextStream(stderr) << "MANAGED_RULE_MATRIX_PROJECTION_REJECTED\n";
            return 1004;
        }
        QTextStream(stdout) << "MANAGED_RULE_MATRIX_PROJECTION_AND_LAYER_PRIORITY_PASS" << Qt::endl;
        if (!NekoGui_sub::MihomoValidator::validate(executable, projected, error)) {
            QTextStream(stderr) << "MANAGED_RULE_MATRIX_PINNED_CORE_REJECTED\n";
            return 1005;
        }
        QTextStream(stdout) << "MANAGED_RULE_MATRIX_PINNED_CORE_PASS" << Qt::endl;
        const QByteArray fakeIpProfile =
            "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 1}]\n"
            "proxy-groups: [{name: select, type: select, proxies: [node]}]\n"
            "rules: ['MATCH,select']\n"
            "dns: {enable: true, enhanced-mode: fake-ip, nameserver: [127.0.0.1], "
            "fake-ip-filter: ['*.example.invalid']}\n";
        NekoGui_sub::ManagedProfile fakeIp, fakeIpProjected;
        fakeIpProjected.source = QByteArray("sentinel-runtime-output");
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(fakeIpProfile, fakeIp, error) ||
            !NekoGui_sub::ManagedRuntimePolicy::checkSelfContained(fakeIp, error) ||
            NekoGui_sub::ManagedRuntimePolicy::projectLoopback(fakeIp, 17891, 17892,
                    QByteArray(64, 'b'), fakeIpProjected, error) ||
            error.isEmpty() || fakeIpProjected.source != QByteArray("sentinel-runtime-output")) {
            QTextStream(stderr) << "MANAGED_FAKE_IP_UNREVIEWED_POLICY_NOT_FAIL_CLOSED\n";
            return 1002;
        }
        QTextStream(stdout) << "MANAGED_FAKE_IP_UNREVIEWED_POLICY_FAIL_CLOSED_PRESERVATION_PASS\n";
    }
    if (rulesOnly) return 0;
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
    using Ownership = NekoGui_sub::CoreOwnership;
    auto &ownership = Ownership::shared();
    if (!ownership.acquire(Ownership::Owner::Legacy, error)) return 34;
    if (child.start(executable, panel, mixedPort, apiPort, token, error) || child.processId() != 0 ||
        ownership.owner() != Ownership::Owner::Legacy || error.isEmpty()) return 35;
    if (!ownership.release(Ownership::Owner::Legacy, error)) return 36;
    if (child.start(executable + ".missing", panel, mixedPort, apiPort, token, error) ||
        child.processId() != 0 || child.state() != NekoGui_sub::ManagedCoreProcess::State::Failed) return 18;
    mixedReservation.close();
    apiReservation.close();
    if (!child.start(executable, panel, mixedPort, apiPort, token, error)) return 6;
    NekoGui_sub::ManagedCoreProcess competing;
    if (ownership.acquire(Ownership::Owner::Legacy, error) ||
        competing.start(executable, panel, mixedPort, apiPort, token, error) || competing.processId() != 0 ||
        ownership.owner() != Ownership::Owner::Managed) return 37;
    QTextStream(stdout) << "MIHOMO_SHARED_CORE_ARBITRATION_PASS\n";
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
    QFile tlsCertificateFile(certificatePath), tlsPrivateKeyFile(privateKeyPath);
    if (!tlsCertificateFile.open(QIODevice::ReadOnly) || !tlsPrivateKeyFile.open(QIODevice::ReadOnly)) return 125;
    const QSslCertificate loopbackCertificate(tlsCertificateFile.readAll());
    const QSslKey loopbackPrivateKey(tlsPrivateKeyFile.readAll(), QSsl::Rsa);
    if (!QSslSocket::supportsSsl() || loopbackCertificate.isNull() || loopbackPrivateKey.isNull()) return 126;
    LoopbackTlsOrigin tlsOrigin;
    tlsOrigin.certificate = loopbackCertificate;
    tlsOrigin.privateKey = loopbackPrivateKey;
    if (!tlsOrigin.listen(QHostAddress::LocalHost, 0)) return 127;
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
    if (!child.stop(error) || child.state() != NekoGui_sub::ManagedCoreProcess::State::Stopped ||
        child.processId() != 0 || !child.stop(error)) return 11;
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
    // Exercise the fail-closed uncertain-ownership boundary with a real owned
    // core, then independently prove and reap that exact process. This is not
    // a simulated TerminateProcess timeout: Windows normally lets our owner
    // kill its child, and the test must never leave an orphan behind.
    {
        NekoGui_sub::ManagedCoreProcess uncertainOwner;
        if (!uncertainOwner.start(executable, panel, mixedPort, apiPort, token, error) ||
            !uncertainOwner.waitReady(10000, error)) return 65;
        const auto uncertainPid = uncertainOwner.processId();
        const auto generation = ownership.generation(Ownership::Owner::Managed);
        if (!uncertainPid || !generation ||
            !ownership.markUncertain(Ownership::Owner::Managed, error, generation) ||
            ownership.state() != Ownership::State::Uncertain) return 66;
        NekoGui_sub::ManagedCoreProcess blockedManaged;
        QString competingError;
        if (ownership.acquire(Ownership::Owner::Legacy, competingError) ||
            blockedManaged.start(executable, panel, mixedPort, apiPort, token, competingError) ||
            blockedManaged.processId() != 0 || uncertainOwner.processId() != uncertainPid ||
            ownership.owner() != Ownership::Owner::Managed ||
            ownership.state() != Ownership::State::Uncertain) return 67;

        struct ReapGuard {
            HANDLE process = nullptr;
            ~ReapGuard() {
                if (!process) return;
                if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
                    TerminateProcess(process, 97);
                    WaitForSingleObject(process, 3000);
                }
                CloseHandle(process);
            }
        } guard{OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(uncertainPid))};
        if (!guard.process) return 68;
        const bool terminated = TerminateProcess(guard.process, 42) &&
                                WaitForSingleObject(guard.process, 3000) == WAIT_OBJECT_0;
        if (!terminated) return 69;
        // The QProcess owner observes the held-handle process as exited and
        // releases uncertainty only after its own cleanup/reap path confirms it.
        if (uncertainOwner.stop(error) || uncertainOwner.processId() != 0 ||
            uncertainOwner.state() != NekoGui_sub::ManagedCoreProcess::State::Failed ||
            ownership.owner() != Ownership::Owner::None ||
            ownership.state() != Ownership::State::Free) return 70;
        QTcpSocket apiAfterUncertain, mixedAfterUncertain;
        apiAfterUncertain.connectToHost(QHostAddress::LocalHost, apiPort);
        mixedAfterUncertain.connectToHost(QHostAddress::LocalHost, mixedPort);
        if (apiAfterUncertain.waitForConnected(500) || mixedAfterUncertain.waitForConnected(500)) return 71;
        // ReapGuard closes its still-signalled handle at scope exit.
        QTextStream(stdout) << "MANAGED_UNCERTAIN_OWNERSHIP_BLOCKS_UNTIL_CONFIRMED_REAP_PASS\n";
    }
    // Exercise the real QProcess forced-cleanup timeout without leaving a child
    // behind: the injected adapter refuses to kill, then a held kernel handle
    // acts as an independent supervisor and guarantees exact-child cleanup.
    {
        NekoGui_sub::ManagedCoreProcess timedOutOwner([](qint64) { return false; });
        if (!timedOutOwner.start(executable, panel, mixedPort, apiPort, token, error) ||
            !timedOutOwner.waitReady(10000, error)) return 72;
        const auto timedOutPid = timedOutOwner.processId();
        struct TimeoutReapGuard {
            HANDLE process = nullptr;
            ~TimeoutReapGuard() {
                if (!process) return;
                if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
                    TerminateProcess(process, 97);
                    WaitForSingleObject(process, 3000);
                }
                CloseHandle(process);
            }
        } guard{OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(timedOutPid))};
        if (!guard.process || !timedOutPid) return 73;
        const bool stopped = timedOutOwner.stop([](qint64) { return false; }, error);
        const auto uncertainGeneration = ownership.generation(Ownership::Owner::Managed);
        NekoGui_sub::ManagedCoreProcess blockedManaged;
        QString blockedError;
        if (stopped || error.isEmpty() || timedOutOwner.state() != NekoGui_sub::ManagedCoreProcess::State::Failed ||
            timedOutOwner.processId() != timedOutPid || ownership.state() != Ownership::State::Uncertain ||
            !uncertainGeneration || ownership.owner() != Ownership::Owner::Managed ||
            ownership.acquire(Ownership::Owner::Legacy, blockedError) ||
            blockedManaged.start(executable, panel, mixedPort, apiPort, token, blockedError) ||
            blockedManaged.processId() != 0 || timedOutOwner.processId() != timedOutPid) return 74;

        const bool reapedExternally = TerminateProcess(guard.process, 42) &&
                                      WaitForSingleObject(guard.process, 3000) == WAIT_OBJECT_0;
        if (!reapedExternally) return 75;
        if (timedOutOwner.stop(error) || timedOutOwner.processId() != 0 ||
            timedOutOwner.state() != NekoGui_sub::ManagedCoreProcess::State::Failed ||
            ownership.owner() != Ownership::Owner::None || ownership.state() != Ownership::State::Free) return 76;
        QTcpSocket apiAfterTimeout, mixedAfterTimeout;
        apiAfterTimeout.connectToHost(QHostAddress::LocalHost, apiPort);
        mixedAfterTimeout.connectToHost(QHostAddress::LocalHost, mixedPort);
        if (apiAfterTimeout.waitForConnected(500) || mixedAfterTimeout.waitForConnected(500)) return 77;
        QTextStream(stdout) << "MANAGED_FORCE_CLEANUP_TIMEOUT_RETURNS_UNCERTAIN_UNTIL_SUPERVISED_REAP_PASS\n";
    }
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
        child.stop(error) || error.isEmpty() || child.processId() != 0 || !portsClosed()) return 30;
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
    QTemporaryDir snapshots;
    if (!snapshots.isValid()) return 38;
    NekoGui_sub::ManagedProfileStore store(snapshots.path());
    const auto validate = [&](const NekoGui_sub::ManagedProfile &candidate, QString &e) {
        return NekoGui_sub::MihomoValidator::validate(executable, candidate, e);
    };
    if (!store.commit(71, source, validate, error)) return 39;
    NekoGui_sub::ManagedSession session;
    if (session.start(store, 71, executable, mixedPort, apiPort, 0, error) || session.processId() != 0) return 47;
    if (!ownership.acquire(Ownership::Owner::Legacy, error)) return 48;
    if (session.start(store, 71, executable, mixedPort, apiPort, 10000, error) ||
        session.groupId() != -1 || session.processId() != 0 || ownership.owner() != Ownership::Owner::Legacy) return 49;
    if (!ownership.release(Ownership::Owner::Legacy, error)) return 50;
    if (session.start(store, 999, executable, mixedPort, apiPort, 10000, error) ||
        session.groupId() != -1 || session.processId() != 0) return 40;
    if (!session.start(store, 71, executable, mixedPort, apiPort, 10000, error) ||
        session.groupId() != 71 || session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready) return 41;
    const auto sessionPid = session.processId();
    if (session.start(store, 72, executable, mixedPort, apiPort, 10000, error) ||
        session.processId() != sessionPid || session.groupId() != 71) return 42;
    if (!session.stop(error) || session.groupId() != -1 || session.processId() != 0 || !portsClosed()) return 43;
    NekoGui_sub::ManagedProfile saved;
    if (!store.load(71, saved, error) || saved.source != source) return 44;
    NekoGui_sub::SubscriptionMetadata expired;
    expired.expiry = QDateTime::currentSecsSinceEpoch() - 60;
    if (!store.commit(72, source, expired, validate, error) ||
        session.start(store, 72, executable, mixedPort, apiPort, 10000, error) || session.processId() != 0) return 45;
    NekoGui_sub::SubscriptionMetadata exhausted;
    exhausted.total = 10;
    exhausted.download = 10;
    exhausted.upload = 0;
    if (!store.commit(73, source, exhausted, validate, error) ||
        session.start(store, 73, executable, mixedPort, apiPort, 10000, error) || session.processId() != 0) return 51;
    if (!session.start(store, 71, executable, mixedPort, apiPort, 10000, error) || !session.stop(error)) return 46;
    // Pinned executable failure must be rejected before the old child is stopped.
    if (!session.start(store, 71, executable, mixedPort, apiPort, 10000, error)) return 75;
    const auto retainedPid = session.processId();
    const auto retainedGeneration = ownership.generation(Ownership::Owner::Managed);
    if (session.reconnect(store, 71, executable + ".missing", mixedPort, apiPort, 10000, error) ||
        error.isEmpty() || session.processId() != retainedPid ||
        ownership.generation(Ownership::Owner::Managed) != retainedGeneration ||
        session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready) return 76;
    // Config validation does not bind the port. Occupy the replacement API
    // endpoint to force a real post-Stop launch/readiness failure, no VPN traffic.
    QTcpServer occupiedApi;
    if (!occupiedApi.listen(QHostAddress::LocalHost, 0)) return 77;
    const QByteArray failedCandidate = source + "# candidate must remain stored after runtime rollback\n";
    if (!store.commit(71, failedCandidate, validate, error)) return 81;
    if (session.reconnect(store, 71, executable, mixedPort, occupiedApi.serverPort(), 500, error) ||
        error.isEmpty() || session.processId() == 0 || session.groupId() != 71 ||
        session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready ||
        session.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Restored ||
        ownership.owner() != Ownership::Owner::Managed ||
        ownership.generation(Ownership::Owner::Managed) <= retainedGeneration) return 78;
    if (!occupiedApi.isListening() || !store.load(71, saved, error) || saved.source != failedCandidate) return 79;
    occupiedApi.close();
    // Restored is running on the previous API port, not the failed candidate's.
    QTcpSocket restoredApi;
    restoredApi.connectToHost(QHostAddress::LocalHost, apiPort);
    if (!restoredApi.waitForConnected(1000)) return 82;
    restoredApi.abort();
    if (!session.stop(error) || !portsClosed()) return 80;
    if (!store.commit(71, source, validate, error)) return 83;
    QTextStream(stdout) << "MANAGED_RECONNECT_PREFLIGHT_AND_BOUNDED_RESTORE_PASS\n";
    // Let the captured working metadata expire naturally, then fail replacement.
    // The current store is healthy; rollback must use the captured OLD expiry.
    NekoGui_sub::SubscriptionMetadata shortLived;
    shortLived.expiry = QDateTime::currentSecsSinceEpoch() + 15;
    if (!store.commit(74, source, shortLived, validate, error) ||
        !session.start(store, 74, executable, mixedPort, apiPort, 10000, error) ||
        shortLived.expired(QDateTime::currentSecsSinceEpoch())) return 84;
    if (!store.commit(74, failedCandidate, validate, error) ||
        !occupiedApi.listen(QHostAddress::LocalHost, 0)) return 85;
    QElapsedTimer expiryDeadline;
    expiryDeadline.start();
    while (!shortLived.expired(QDateTime::currentSecsSinceEpoch()) && expiryDeadline.elapsed() < 20000) {
        QEventLoop pause;
        QTimer::singleShot(25, &pause, &QEventLoop::quit);
        pause.exec();
    }
    if (!shortLived.expired(QDateTime::currentSecsSinceEpoch()) ||
        session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready) return 86;
    if (session.reconnect(store, 74, executable, mixedPort, occupiedApi.serverPort(), 500, error) ||
        error.isEmpty() || session.processId() != 0 || session.groupId() != -1 ||
        session.state() != NekoGui_sub::ManagedCoreProcess::State::Failed ||
        session.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Stopped ||
        ownership.owner() != Ownership::Owner::None || !portsClosed() ||
        !occupiedApi.isListening() || !store.load(74, saved, error) || saved.source != failedCandidate) return 87;
    occupiedApi.close();
    if (!session.start(store, 74, executable, mixedPort, apiPort, 10000, error) ||
        !session.stop(error) || !portsClosed()) return 88;
    QTextStream(stdout) << "MANAGED_RECONNECT_EXPIRED_PREVIOUS_RESTORE_REFUSED_PASS\n";
    // Exercise production stop/kill/reap with a refused or throwing adapter.
    // Exact generation advance on explicit recovery proves no hidden restart.
    for (const bool throws : {false, true}) {
        int signalCalls = 0;
        qint64 signaledPid = 0;
        NekoGui_sub::ManagedSession refusedStop([&](qint64 childPid) -> bool {
            ++signalCalls;
            signaledPid = childPid;
            if (throws) throw 1;
            return false;
        });
        if (!refusedStop.start(store, 71, executable, mixedPort, apiPort, 10000, error)) return 96;
        const auto oldPid = refusedStop.processId();
        const auto oldGeneration = ownership.generation(Ownership::Owner::Managed);
        if (!store.commit(71, failedCandidate, validate, error) ||
            refusedStop.reconnect(store, 71, executable, mixedPort, apiPort, 10000, error) ||
            error.isEmpty() || signalCalls != 1 || signaledPid != oldPid ||
            refusedStop.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::StopFailed ||
            refusedStop.state() != NekoGui_sub::ManagedCoreProcess::State::Failed ||
            refusedStop.processId() != 0 || refusedStop.groupId() != -1 ||
            ownership.owner() != Ownership::Owner::None || !portsClosed() ||
            !store.load(71, saved, error) || saved.source != failedCandidate) return 97;
        if (!session.start(store, 71, executable, mixedPort, apiPort, 10000, error) ||
            ownership.generation(Ownership::Owner::Managed) != oldGeneration + 1 ||
            !session.stop(error) || !portsClosed()) return 98;
    }
    if (!store.commit(71, source, validate, error)) return 99;
    QTextStream(stdout) << "MANAGED_RECONNECT_FORCED_STOP_NO_REPLACEMENT_OR_RESTORE_PASS cases=2\n";
    if (!session.start(store, 71, executable, mixedPort, apiPort, 10000, error)) return 102;
    int fetchCalls = 0;
    int fetchMode = 0;
    const auto refreshFetch = [&](const NekoGui_sub::ManagedSubscriptionRequest &request, const QString &identity,
                                  NekoGui_sub::SubscriptionDownload &download, QString &, const std::atomic_bool *) {
        ++fetchCalls;
        if (request.url.scheme() != "https" || identity.isEmpty() || fetchMode == 0) return false;
        download.source = fetchMode == 1 ? source + "rule-providers: {external: {type: http, url: 'https://example.invalid/rules', path: rules.yaml}}\n"
                                        : failedCandidate;
        return true;
    };
    const auto refreshApply = [&](const QString &core, int timeout, int port) {
        return session.refreshAndReconnect(store, 71, QUrl("https://example.invalid/synthetic"), "1.0.0",
            snapshots.path(), refreshFetch, core, mixedPort, port, timeout, error);
    };
    const auto refreshPid = session.processId();
    const auto refreshGeneration = ownership.generation(Ownership::Owner::Managed);
    if (refreshApply(executable, 0, apiPort) || refreshApply(executable + ".missing", 10000, apiPort) || fetchCalls != 0)
        return 103;
    for (int mode : {0, 1}) {
        fetchMode = mode;
        if (refreshApply(executable, 10000, apiPort) || error.isEmpty() ||
            session.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected ||
            session.processId() != refreshPid || session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready ||
            ownership.generation(Ownership::Owner::Managed) != refreshGeneration ||
            !store.load(71, saved, error) || saved.source != source) return 104;
    }
    fetchMode = 2;
    if (!refreshApply(executable, 10000, apiPort) || fetchCalls != 3 ||
        session.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Applied ||
        !store.load(71, saved, error) || saved.source != failedCandidate) return 105;
    if (!occupiedApi.listen(QHostAddress::LocalHost, 0) || refreshApply(executable, 500, occupiedApi.serverPort()) ||
        session.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Restored ||
        session.state() != NekoGui_sub::ManagedCoreProcess::State::Ready || fetchCalls != 4 ||
        !store.load(71, saved, error) || saved.source != failedCandidate) return 106;
    occupiedApi.close();
    if (!session.stop(error) || !portsClosed() || !store.commit(71, source, validate, error)) return 107;
    QTextStream(stdout) << "MANAGED_REFRESH_VALIDATE_STORE_APPLY_AND_RESTORE_PASS\n";
    QTextStream(stdout) << "MANAGED_SNAPSHOT_SESSION_READINESS_STOP_PASS\n";
    // End-to-end endpoint transition over two local SOCKS5 upstreams. Mihomo
    // must establish a real outbound connection through endpoint A, then a
    // refresh/apply changes the profile to B; subsequent traffic must use B
    // while A receives no more connections. All destinations stay loopback.
    {
        const auto endpointProfile = [&](quint16 port, const QByteArray &username = QByteArray{},
                                         const QByteArray &password = QByteArray{}) {
            auto proxy = QByteArray("proxies: [{name: node, type: socks5, server: 127.0.0.1, port: ") +
                QByteArray::number(port) +
                QByteArray(", username: '") + username + QByteArray("', password: '") + password + "'}]\n";
            if (username.isEmpty() && password.isEmpty()) {
                proxy = QByteArray("proxies: [{name: node, type: socks5, server: 127.0.0.1, port: ") +
                    QByteArray::number(port) + "}]\n";
            }
            return proxy +
                "proxy-groups: [{name: custom-main, type: select, proxies: [node]}]\n"
                "rules: ['IP-CIDR,192.0.2.0/24,DIRECT,no-resolve', "
                "'IP-CIDR,127.0.0.1/32,custom-main,no-resolve', 'MATCH,DIRECT']\n"
                "dns: {enable: false, nameserver: [127.0.0.1]}\n";
        };
        int endpointARequests = 0, endpointBRequests = 0;
        int authenticatedEndpointBRequests = 0;
        const auto configureSocksEndpoint = [&](QTcpServer &server, int &connectRequests,
                                                const QByteArray &expectedUsername = QByteArray{},
                                                const QByteArray &expectedPassword = QByteArray{},
                                                int *authenticatedRequests = nullptr) {
            QObject::connect(&server, &QTcpServer::newConnection, &app,
                [&, expectedUsername, expectedPassword, authenticatedRequests] {
                while (server.hasPendingConnections()) {
                    auto *client = server.nextPendingConnection();
                    auto *upstream = new QTcpSocket(client);
                    auto *buffer = new QByteArray;
                    auto *stage = new int(0);
                    client->setProperty("fixture-buffer", QVariant::fromValue<void *>(buffer));
                    client->setProperty("fixture-stage", QVariant::fromValue<void *>(stage));
                    QObject::connect(client, &QTcpSocket::disconnected, client, &QObject::deleteLater);
                    QObject::connect(client, &QObject::destroyed, [buffer, stage] { delete buffer; delete stage; });
                    QObject::connect(client, &QTcpSocket::readyRead, client,
                        [&, client, upstream, buffer, stage, expectedUsername, expectedPassword, authenticatedRequests] {
                        if (*stage == 4) {
                            upstream->write(client->readAll());
                            return;
                        }
                        *buffer += client->readAll();
                        if (*stage == 0 && buffer->size() >= 3) {
                            const auto methodCount = static_cast<quint8>((*buffer)[1]);
                            if (static_cast<quint8>((*buffer)[0]) != 5 || methodCount == 0 ||
                                buffer->size() < 2 + methodCount) {
                                if (buffer->size() < 2 ||
                                    (static_cast<quint8>((*buffer)[0]) == 5 && buffer->size() < 2 + methodCount)) return;
                                client->disconnectFromHost();
                                return;
                            }
                            const bool requireAuth = !expectedUsername.isEmpty() || !expectedPassword.isEmpty();
                            const auto requiredMethod = requireAuth ? quint8(2) : quint8(0);
                            bool offered = false;
                            for (int i = 0; i < methodCount; ++i)
                                offered = offered || static_cast<quint8>((*buffer)[2 + i]) == requiredMethod;
                            if (!offered) {
                                client->write(QByteArray::fromHex("05ff"));
                                client->disconnectFromHost();
                                return;
                            }
                            *buffer = buffer->mid(2 + methodCount);
                            *stage = requireAuth ? 1 : 2;
                            client->write(QByteArray::fromHex(requireAuth ? "0502" : "0500"));
                        }
                        if (*stage == 1 && buffer->size() >= 2) {
                            const auto usernameLength = static_cast<quint8>((*buffer)[1]);
                            if (static_cast<quint8>((*buffer)[0]) != 1 || usernameLength == 0) {
                                client->disconnectFromHost();
                                return;
                            }
                            if (buffer->size() < 3 + usernameLength) return;
                            const auto passwordLength = static_cast<quint8>((*buffer)[2 + usernameLength]);
                            const auto authLength = 3 + usernameLength + passwordLength;
                            if (passwordLength == 0 || buffer->size() < authLength) return;
                            const auto actualUsername = buffer->mid(2, usernameLength);
                            const auto actualPassword = buffer->mid(3 + usernameLength, passwordLength);
                            *buffer = buffer->mid(authLength);
                            if (actualUsername != expectedUsername || actualPassword != expectedPassword) {
                                client->write(QByteArray::fromHex("0101"));
                                client->disconnectFromHost();
                                return;
                            }
                            client->write(QByteArray::fromHex("0100"));
                            if (authenticatedRequests) ++*authenticatedRequests;
                            *stage = 2;
                        }
                        if (*stage == 2 && buffer->size() >= 10) {
                            const auto request = *buffer;
                            *buffer = buffer->mid(10);
                            const auto destinationPort = (static_cast<quint8>(request[8]) << 8) |
                                                         static_cast<quint8>(request[9]);
                            if (static_cast<quint8>(request[0]) != 5 || static_cast<quint8>(request[1]) != 1 ||
                                static_cast<quint8>(request[3]) != 1 || destinationPort != origin.serverPort()) {
                                client->write(QByteArray::fromHex("05050001000000000000"));
                                client->disconnectFromHost();
                                return;
                            }
                            ++connectRequests;
                            *stage = 3;
                            QObject::connect(upstream, &QTcpSocket::connected, client, [client, upstream, buffer, stage] {
                                client->write(QByteArray::fromHex("05000001000000000000"));
                                *stage = 4;
                                if (!buffer->isEmpty()) upstream->write(*buffer);
                                buffer->clear();
                            });
                            QObject::connect(upstream, &QTcpSocket::readyRead, client,
                                [client, upstream, stage] { if (*stage == 4) client->write(upstream->readAll()); });
                            upstream->connectToHost(QHostAddress::LocalHost, origin.serverPort());
                        }
                    });
                    QObject::connect(upstream, &QTcpSocket::errorOccurred, client,
                        [client](QAbstractSocket::SocketError) { client->disconnectFromHost(); });
                }
            });
        };
        QTcpServer endpointA, endpointB;
        if (!endpointA.listen(QHostAddress::LocalHost, 0) || !endpointB.listen(QHostAddress::LocalHost, 0)) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_LISTEN_FAILED\n";
            return 112;
        }
        configureSocksEndpoint(endpointA, endpointARequests);
        const QByteArray syntheticUsername("fixture-user"), syntheticPassword("fixture-pass");
        configureSocksEndpoint(endpointB, endpointBRequests, syntheticUsername, syntheticPassword,
                                &authenticatedEndpointBRequests);
        const auto profileA = endpointProfile(endpointA.serverPort());
        const auto profileB = endpointProfile(endpointB.serverPort(), syntheticUsername, syntheticPassword);
        NekoGui_sub::ManagedProfile orderedProfile;
        if (!NekoGui_sub::ManagedProfile::ParseMihomo(profileA, orderedProfile, error) ||
            orderedProfile.rules != QStringList{
                "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
                "IP-CIDR,127.0.0.1/32,custom-main,no-resolve",
                "MATCH,DIRECT"}) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_PROFILE_REJECTED\n";
            return 118;
        }
        if (!store.commit(75, profileA, validate, error)) {
            QTextStream(stderr) << "ENDPOINT_TRANSITION_PROFILE_A_REJECTED: " << error << "\n";
            return 113;
        }
        NekoGui_sub::ManagedSession endpointSession;
        if (!endpointSession.start(store, 75, executable, mixedPort, apiPort, 10000, error)) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_SESSION_START_FAILED: " << error << "\n";
            return 114;
        }
        const auto issueDataPathRequest = [&] {
            QTcpSocket client;
            client.connectToHost(QHostAddress::LocalHost, mixedPort);
            if (!client.waitForConnected(1000)) return false;
            const auto address = QByteArray("127.0.0.1:") + QByteArray::number(origin.serverPort());
            const auto request = "GET http://" + address + "/managed-smoke HTTP/1.1\r\nHost: " +
                address + "\r\nConnection: close\r\n\r\n";
            if (client.write(request) != request.size()) return false;
            QByteArray received;
            QEventLoop loop;
            QTimer deadline;
            deadline.setSingleShot(true);
            QObject::connect(&client, &QTcpSocket::readyRead, &loop, [&] { received += client.readAll(); });
            QObject::connect(&client, &QTcpSocket::disconnected, &loop, &QEventLoop::quit);
            QObject::connect(&deadline, &QTimer::timeout, &loop, [&] { client.abort(); loop.quit(); });
            deadline.start(5000);
            if (client.state() != QAbstractSocket::UnconnectedState) loop.exec();
            received += client.readAll();
            return received.contains("HTTP/1.1 200") && received.endsWith("managed-path-pass");
        };
        if (!issueDataPathRequest() || endpointARequests != 1) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_ENDPOINT_A_FAILED requestsA=" << endpointARequests << "\n";
            return 115;
        }
        const auto switchFetch = [&](const NekoGui_sub::ManagedSubscriptionRequest &, const QString &,
                                     NekoGui_sub::SubscriptionDownload &download, QString &, const std::atomic_bool *) {
            download.source = profileB;
            download.metadata.title = QStringLiteral("Synthetic endpoint B");
            return true;
        };
        if (!endpointSession.refreshAndReconnect(store, 75, QUrl("https://example.invalid/autotune"),
                "1.0.0", snapshots.path(), switchFetch, executable, mixedPort, apiPort, 10000, error) ||
            endpointSession.reconnectOutcome() != NekoGui_sub::ManagedSession::ReconnectOutcome::Applied ||
            !store.load(75, saved, error) || saved.source != profileB) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_RECONNECT_FAILED: " << error << "\n";
            return 116;
        }
        if (!issueDataPathRequest() || endpointARequests != 1 || endpointBRequests != 1 ||
            authenticatedEndpointBRequests != 1 ||
            originRequests != 3 || !endpointSession.stop(error) || !portsClosed()) {
            QTextStream(stderr) << "SOCKS_AUTH_FIXTURE_ENDPOINT_B_FAILED requestsA=" << endpointARequests
                                << " requestsB=" << endpointBRequests
                                << " authenticated=" << authenticatedEndpointBRequests
                                << " origin=" << originRequests << "\n";
            return 117;
        }
        QTextStream(stdout) << "MANAGED_RULE_ORDER_CUSTOM_GROUP_NO_RESOLVE_LOOPBACK_PASS\n";
        QTextStream(stdout) << "MANAGED_SOCKS5_USERNAME_PASSWORD_AUTHENTICATION_PASS requests=1\n";
        QTextStream(stdout) << "MANAGED_REFRESH_ENDPOINT_A_TO_B_LOOPBACK_DATA_PATH_TRANSITION_PASS requestsA=1 requestsB=1\n";
    }
    // End-to-end SOCKS5 UDP ASSOCIATE through the managed mixed listener,
    // pinned mihomo, a synthetic local SOCKS5 UDP relay, and a localhost UDP
    // origin. No public destinations, TUN, or system proxy are involved.
    {
        LoopbackSocks5UdpEndpoint endpoint;
        if (!endpoint.start(error)) {
            QTextStream(stderr) << "SOCKS5_UDP_FIXTURE_START_FAILED: " << error << "\n";
            return 128;
        }
        const auto udpProfile = QByteArray("proxies: [{name: udp-node, type: socks5, server: 127.0.0.1, port: ") +
            QByteArray::number(endpoint.controlServer.serverPort()) +
            ", udp: true}]\n"
            "proxy-groups: [{name: udp-main, type: select, proxies: [udp-node]}]\n"
            "rules: ['IP-CIDR,127.0.0.1/32,udp-main,no-resolve', 'MATCH,DIRECT']\n"
            "dns: {enable: false, nameserver: [127.0.0.1]}\n";
        if (!store.commit(77, udpProfile, validate, error)) {
            QTextStream(stderr) << "SOCKS5_UDP_FIXTURE_PROFILE_REJECTED: " << error << "\n";
            return 129;
        }
        NekoGui_sub::ManagedSession udpSession;
        if (!udpSession.start(store, 77, executable, mixedPort, apiPort, 10000, error)) {
            QTextStream(stderr) << "SOCKS5_UDP_FIXTURE_SESSION_START_FAILED: " << error << "\n";
            return 130;
        }
        QTcpSocket control;
        control.connectToHost(QHostAddress::LocalHost, mixedPort);
        if (!control.waitForConnected(1000) || control.write(QByteArray::fromHex("050100")) != 3) return 131;
        auto waitForControlBytes = [&](int minimum) {
            QEventLoop waitLoop;
            QTimer timeout;
            timeout.setSingleShot(true);
            QObject::connect(&control, &QTcpSocket::readyRead, &waitLoop, &QEventLoop::quit);
            QObject::connect(&timeout, &QTimer::timeout, &waitLoop, &QEventLoop::quit);
            timeout.start(3000);
            while (control.bytesAvailable() < minimum && control.state() == QAbstractSocket::ConnectedState &&
                   timeout.isActive()) waitLoop.exec();
            return control.bytesAvailable() >= minimum;
        };
        if (!waitForControlBytes(2) || control.read(2) != QByteArray::fromHex("0500") ||
            control.write(QByteArray::fromHex("05030001000000000000")) != 10 || !waitForControlBytes(10)) {
            QTextStream(stderr) << "SOCKS5_UDP_ASSOCIATE_CONTROL_FAILED\n";
            udpSession.stop(error);
            return 132;
        }
        const auto associateReply = control.read(10);
        if (associateReply.size() != 10 || associateReply.left(4) != QByteArray::fromHex("05000001")) {
            QTextStream(stderr) << "SOCKS5_UDP_ASSOCIATE_REPLY_INVALID bytes=" << associateReply.toHex() << "\n";
            udpSession.stop(error);
            return 133;
        }
        const auto relayAddress = QHostAddress(QStringLiteral("%1.%2.%3.%4")
            .arg(static_cast<quint8>(associateReply[4])).arg(static_cast<quint8>(associateReply[5]))
            .arg(static_cast<quint8>(associateReply[6])).arg(static_cast<quint8>(associateReply[7])));
        const auto relayPort = quint16((static_cast<quint8>(associateReply[8]) << 8) |
                                       static_cast<quint8>(associateReply[9]));
        if (relayAddress != QHostAddress::LocalHost || relayPort == 0) {
            QTextStream(stderr) << "SOCKS5_UDP_ASSOCIATE_RELAY_NOT_LOOPBACK\n";
            udpSession.stop(error);
            return 134;
        }
        QUdpSocket udpClient;
        if (!udpClient.bind(QHostAddress::LocalHost, 0)) {
            udpSession.stop(error);
            return 135;
        }
        QByteArray packet = QByteArray::fromHex("000000017f000001") +
            QByteArray(1, char((endpoint.originSocket.localPort() >> 8) & 0xff)) +
            QByteArray(1, char(endpoint.originSocket.localPort() & 0xff)) + "synthetic-udp-request";
        if (udpClient.writeDatagram(packet, relayAddress, relayPort) != packet.size()) {
            udpSession.stop(error);
            return 136;
        }
        QEventLoop responseLoop;
        QTimer responseTimeout;
        responseTimeout.setSingleShot(true);
        QObject::connect(&udpClient, &QUdpSocket::readyRead, &responseLoop, &QEventLoop::quit);
        QObject::connect(&responseTimeout, &QTimer::timeout, &responseLoop, &QEventLoop::quit);
        responseTimeout.start(5000);
        while (!udpClient.hasPendingDatagrams() && responseTimeout.isActive()) responseLoop.exec();
        QByteArray udpResponse;
        QHostAddress responseAddress;
        quint16 responsePort = 0;
        if (udpClient.hasPendingDatagrams()) {
            udpResponse.resize(int(udpClient.pendingDatagramSize()));
            const auto length = udpClient.readDatagram(udpResponse.data(), udpResponse.size(),
                                                       &responseAddress, &responsePort);
            if (length >= 0) udpResponse.resize(int(length));
        }
        const QByteArray expectedUdpHeader = QByteArray::fromHex("000000017f000001") +
            QByteArray(1, char((endpoint.originSocket.localPort() >> 8) & 0xff)) +
            QByteArray(1, char(endpoint.originSocket.localPort() & 0xff));
        const bool udpPathPassed = udpResponse == expectedUdpHeader + "managed-udp-pass" &&
            responseAddress == relayAddress && responsePort == relayPort && endpoint.associations == 1 &&
            endpoint.relayedDatagrams == 1 && endpoint.originDatagrams == 1;
        control.disconnectFromHost();
        if (!udpPathPassed || !udpSession.stop(error) || !portsClosed()) {
            QTextStream(stderr) << "SOCKS5_UDP_LOOPBACK_DATA_PATH_FAILED associations=" << endpoint.associations
                                << " relayed=" << endpoint.relayedDatagrams
                                << " origin=" << endpoint.originDatagrams
                                << " response=" << udpResponse.toHex() << "\n";
            return 137;
        }
        QTextStream(stdout) << "MANAGED_SOCKS5_UDP_LOOPBACK_DATA_PATH_PASS associations=1 datagrams=1\n";
    }
    // Exercise a distinct HTTP-proxy CONNECT outbound path with an entirely
    // local proxy fixture and a synthetic loopback TLS origin. No public traffic.
    {
        QTcpServer httpProxy;
        if (!httpProxy.listen(QHostAddress::LocalHost, 0)) return 119;
        int httpProxyConnections = 0, httpProxyRequests = 0;
        QObject::connect(&httpProxy, &QTcpServer::newConnection, &app, [&] {
            while (httpProxy.hasPendingConnections()) {
                auto *client = httpProxy.nextPendingConnection();
                ++httpProxyConnections;
                auto *upstream = new QTcpSocket(client);
                QObject::connect(client, &QTcpSocket::disconnected, client, &QObject::deleteLater);
                QObject::connect(client, &QTcpSocket::readyRead, client, [&, client, upstream] {
                    if (client->property("http-proxy-tunnel").toBool()) {
                        upstream->write(client->readAll());
                        return;
                    }
                    const auto bytes = client->readAll();
                    auto pending = client->property("http-proxy-buffer").toByteArray() + bytes;
                    const auto headerEnd = pending.indexOf("\r\n\r\n");
                    if (headerEnd < 0) {
                        client->setProperty("http-proxy-buffer", pending);
                        return;
                    }
                    const auto header = pending.left(headerEnd + 4);
                    const auto expectedTarget = QByteArray("CONNECT 127.0.0.1:") +
                        QByteArray::number(tlsOrigin.serverPort()) + " HTTP/1.1\r\n";
                    if (!header.startsWith(expectedTarget)) {
                        client->write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        client->disconnectFromHost();
                        return;
                    }
                    client->setProperty("http-proxy-tunnel", true);
                    ++httpProxyRequests;
                    const auto trailing = pending.mid(headerEnd + 4);
                    QObject::connect(upstream, &QTcpSocket::connected, client, [client, upstream, trailing] {
                        client->write("HTTP/1.1 200 Connection Established\r\n\r\n");
                        if (!trailing.isEmpty()) upstream->write(trailing);
                    });
                    QObject::connect(upstream, &QTcpSocket::readyRead, client,
                        [client, upstream] { client->write(upstream->readAll()); });
                    QObject::connect(upstream, &QTcpSocket::disconnected, client,
                        [client] { client->disconnectFromHost(); });
                    upstream->connectToHost(QHostAddress::LocalHost, tlsOrigin.serverPort());
                });
            }
        });
        const auto httpProfile = QByteArray("proxies: [{name: http-node, type: http, server: 127.0.0.1, port: ") +
            QByteArray::number(httpProxy.serverPort()) +
            "}]\nproxy-groups: [{name: http-main, type: select, proxies: [http-node]}]\n"
            "rules: ['IP-CIDR,127.0.0.1/32,http-main,no-resolve', 'MATCH,DIRECT']\n"
            "dns: {enable: false, nameserver: [127.0.0.1]}\n";
        if (!store.commit(76, httpProfile, validate, error)) {
            QTextStream(stderr) << "HTTP_PROXY_FIXTURE_PROFILE_REJECTED: " << error << "\n";
            return 120;
        }
        NekoGui_sub::ManagedSession httpSession;
        if (!httpSession.start(store, 76, executable, mixedPort, apiPort, 10000, error)) {
            QTextStream(stderr) << "HTTP_PROXY_FIXTURE_SESSION_START_FAILED: " << error << "\n";
            return 121;
        }
        QNetworkAccessManager tlsClient;
        tlsClient.setProxy(QNetworkProxy(QNetworkProxy::HttpProxy, "127.0.0.1", mixedPort));
        QNetworkRequest tlsRequest(QUrl(QString("https://localhost:%1/managed-tls").arg(tlsOrigin.serverPort())));
        auto trustedTls = QSslConfiguration::defaultConfiguration();
        trustedTls.setCaCertificates({loopbackCertificate});
        tlsRequest.setSslConfiguration(trustedTls);
        auto *tlsReply = tlsClient.get(tlsRequest);
        tlsReply->setReadBufferSize(8192);
        QEventLoop loop;
        QTimer deadline;
        deadline.setSingleShot(true);
        QObject::connect(tlsReply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&] { tlsReply->abort(); loop.quit(); });
        deadline.start(5000);
        loop.exec();
        const auto tlsBody = tlsReply->readAll();
        const auto tlsNetworkError = tlsReply->error();
        tlsReply->deleteLater();
        if (tlsNetworkError != QNetworkReply::NoError || tlsBody != "managed-tls-path-pass" ||
            httpProxyRequests != 1 || tlsOrigin.requests != 1 || !httpSession.stop(error) || !portsClosed()) {
            QTextStream(stderr) << "HTTP_PROXY_FIXTURE_DATA_PATH_FAILED connections=" << httpProxyConnections
                                << " requests=" << httpProxyRequests
                                << " tlsOrigin=" << tlsOrigin.requests
                                << " error=" << int(tlsNetworkError)
                                << " body=" << tlsBody.toHex() << "\n";
            return 124;
        }
        QTextStream(stdout) << "MANAGED_HTTP_PROXY_TLS_CONNECT_LOOPBACK_DATA_PATH_PASS requests=1\n";
    }
    {
        NekoGui_sub::ManagedSessionController controller;
        const auto initialSnapshot = controller.snapshot();
        if (initialSnapshot.value("schemaVersion").toInt() != 1 ||
            initialSnapshot.value("state").toString() != "stopped" ||
            initialSnapshot.value("scope").toString() != "loopback-only" ||
            initialSnapshot.value("vpnConnected").toBool() || initialSnapshot.size() != 8) return 61;
        bool completed = false, succeeded = false;
        bool reconnectOutcomeReceived = false;
        int reconnectOutcome = -1;
        int reconnectCompletions = 0;
        QString completedRequestId;
        bool correlatedSuccess = false;
        int correlatedOutcome = -1;
        QString correlatedError;
        QJsonObject correlatedSnapshot;
        int status = -1, group = -1;
        qint64 pid = 0;
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::statusChanged,
            &app, [&](int s, int g, qint64 p) { status = s; group = g; pid = p; });
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::operationFinished,
            &app, [&](bool ok, const QString &) { completed = true; succeeded = ok; });
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::reconnectFinished,
            &app, [&](int outcome) { reconnectOutcomeReceived = true; reconnectOutcome = outcome; });
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::reconnectCompleted,
            &app, [&](const QString &requestId, bool ok, int outcome, const QString &message, const QJsonObject &snapshot) {
                ++reconnectCompletions;
                completedRequestId = requestId;
                correlatedSuccess = ok;
                correlatedOutcome = outcome;
                correlatedError = message;
                correlatedSnapshot = snapshot;
            });
        auto await = [&] {
            QElapsedTimer timer;
            timer.start();
            while (!completed && timer.elapsed() < 30000) {
                QEventLoop pause;
                QTimer::singleShot(10, &pause, &QEventLoop::quit);
                pause.exec();
            }
            return completed;
        };
        auto awaitReconnectOutcome = [&] {
            QElapsedTimer timer;
            timer.start();
            while (!reconnectOutcomeReceived && timer.elapsed() < 30000) {
                QEventLoop pause;
                QTimer::singleShot(10, &pause, &QEventLoop::quit);
                pause.exec();
            }
            return reconnectOutcomeReceived;
        };
        if (!controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !controller.busy() || controller.stop() ||
            !await() || !succeeded || controller.busy() || group != 71 || pid == 0 ||
            status != static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Ready)) return 52;
        const auto readySnapshot = controller.snapshot();
        if (readySnapshot.value("state").toString() != "ready" ||
            !readySnapshot.value("controllerReady").toBool() || readySnapshot.value("vpnConnected").toBool() ||
            readySnapshot.value("groupId").toInt() != 71 || readySnapshot.contains("token") ||
            readySnapshot.contains("processId")) return 62;
        completed = false;
        reconnectOutcomeReceived = false;
        const auto beforeReconnect = pid;
        const auto beforeReconnectGeneration = ownership.generation(Ownership::Owner::Managed);
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 0, "reject-timeout") ||
            !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectCompletions != 1 || completedRequestId != "reject-timeout" ||
            correlatedSuccess || correlatedError.isEmpty() || correlatedOutcome != reconnectOutcome ||
            correlatedSnapshot != controller.snapshot() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected) ||
            pid != beforeReconnect ||
            !controller.snapshot().value("controllerReady").toBool()) return 65;
        completed = false;
        reconnectOutcomeReceived = false;
        if (!controller.reconnect(snapshots.path(), 72, executable, mixedPort, apiPort, 10000) ||
            !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected) ||
            pid != beforeReconnect) return 66;
        // A valid stored document may still be rejected by execution policy.
        const QByteArray resourceCandidate = source + "rule-providers: {external: {type: http, url: 'https://example.invalid/rules', path: rules.yaml}}\n";
        const auto parserOnly = [](const NekoGui_sub::ManagedProfile &, QString &) { return true; };
        if (!store.commit(71, resourceCandidate, parserOnly, error)) return 67;
        completed = false;
        reconnectOutcomeReceived = false;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected) ||
            pid != beforeReconnect ||
            !controller.snapshot().value("controllerReady").toBool()) return 68;
        if (!store.commit(71, source, expired, validate, error)) return 69;
        completed = false;
        reconnectOutcomeReceived = false;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected) ||
            pid != beforeReconnect) return 70;
        const auto replacementSource = source + "# refreshed synthetic snapshot\n";
        if (!store.commit(71, replacementSource, validate, error)) return 71;
        completed = false;
        reconnectOutcomeReceived = false;
        const auto beforeAppliedCompletions = reconnectCompletions;
        if (controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 10000, QString(129, 'x')) ||
            controller.busy() || reconnectCompletions != beforeAppliedCompletions) return 100;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 10000, "apply-profile") ||
            !controller.busy() || controller.stop() ||
            controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 0, "busy-refused") ||
            !await() || !succeeded || !awaitReconnectOutcome() ||
            reconnectCompletions != beforeAppliedCompletions + 1 || completedRequestId != "apply-profile" ||
            !correlatedSuccess || !correlatedError.isEmpty() || correlatedOutcome != reconnectOutcome ||
            correlatedSnapshot != controller.snapshot() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Applied) ||
            pid == 0 ||
            group != 71 || !controller.snapshot().value("controllerReady").toBool() ||
            ownership.generation(Ownership::Owner::Managed) <= beforeReconnectGeneration) return 72;
        if (!store.load(71, saved, error) || saved.source != replacementSource) return 73;
        if (!occupiedApi.listen(QHostAddress::LocalHost, 0) ||
            !store.commit(71, failedCandidate, validate, error)) return 89;
        const auto beforeRestoreGeneration = ownership.generation(Ownership::Owner::Managed);
        completed = false;
        reconnectOutcomeReceived = false;
        const auto beforeRestoredCompletions = reconnectCompletions;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, occupiedApi.serverPort(), 500, "restore-profile") ||
            !controller.busy() || controller.stop() || !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectCompletions != beforeRestoredCompletions + 1 || completedRequestId != "restore-profile" ||
            correlatedSuccess || correlatedError.isEmpty() || correlatedOutcome != reconnectOutcome ||
            correlatedSnapshot != controller.snapshot() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Restored) ||
            controller.busy() || group != 71 || pid == 0 ||
            status != static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Ready) ||
            !controller.snapshot().value("controllerReady").toBool() ||
            controller.snapshot().value("vpnConnected").toBool() ||
            ownership.owner() != Ownership::Owner::Managed ||
            ownership.generation(Ownership::Owner::Managed) <= beforeRestoreGeneration ||
            !occupiedApi.isListening() || !store.load(71, saved, error) || saved.source != failedCandidate) return 90;
        QTcpSocket controllerRestoredApi;
        controllerRestoredApi.connectToHost(QHostAddress::LocalHost, apiPort);
        if (!controllerRestoredApi.waitForConnected(1000)) return 91;
        controllerRestoredApi.abort();
        occupiedApi.close();
        QTextStream(stdout) << "MANAGED_CONTROLLER_RESTORED_OUTCOME_READY_FALSE_SUCCESS_PASS\n";
        // Reclaim the OLD API only after the old child exits. This real local
        // listener makes rollback fail without injecting lifecycle/ownership state.
        QTcpServer occupiedOldApi;
        if (occupiedOldApi.listen(QHostAddress::LocalHost, apiPort) ||
            !occupiedApi.listen(QHostAddress::LocalHost, 0)) return 92;
        QTimer claimOldApi;
        claimOldApi.setInterval(5);
        QObject::connect(&claimOldApi, &QTimer::timeout, &app, [&] {
            if (!occupiedOldApi.isListening()) occupiedOldApi.listen(QHostAddress::LocalHost, apiPort);
        });
        claimOldApi.start();
        completed = false;
        reconnectOutcomeReceived = false;
        const auto beforeFailedCompletions = reconnectCompletions;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, occupiedApi.serverPort(), 2000, "restore-failed") ||
            !await() || succeeded || !awaitReconnectOutcome() ||
            reconnectCompletions != beforeFailedCompletions + 1 || completedRequestId != "restore-failed" ||
            correlatedSuccess || correlatedError.isEmpty() || correlatedOutcome != reconnectOutcome ||
            correlatedSnapshot != controller.snapshot() ||
            reconnectOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::RestoreFailed) ||
            controller.busy() || group != -1 || pid != 0 ||
            status != static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Failed) ||
            controller.snapshot().value("controllerReady").toBool() ||
            controller.snapshot().value("vpnConnected").toBool() ||
            ownership.owner() != Ownership::Owner::None ||
            !occupiedOldApi.isListening() || !occupiedApi.isListening() ||
            !store.load(71, saved, error) || saved.source != failedCandidate) return 93;
        claimOldApi.stop();
        occupiedOldApi.close();
        occupiedApi.close();
        if (!portsClosed()) return 94;
        completed = false;
        if (!controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !await() || !succeeded || pid == 0 || group != 71 ||
            reconnectCompletions != beforeFailedCompletions + 1 ||
            correlatedSnapshot.value("state").toString() != "failed" ||
            correlatedSnapshot.value("busy").toBool()) return 95;
        QTextStream(stdout) << "MANAGED_RECONNECT_CORRELATED_IMMUTABLE_COMPLETION_PASS\n";
        QTextStream(stdout) << "MANAGED_CONTROLLER_RESTORE_FAILED_CLEANUP_EXPLICIT_RECOVERY_PASS\n";
        if (!store.commit(71, source, validate, error)) return 74;
        QTextStream(stdout) << "MANAGED_CONTROLLED_RECONNECT_PREFLIGHT_PRESERVATION_PASS\n";
        // Direct signal observers must not accept a new command before ALL
        // compatibility notifications for the completed operation are delivered.
        int reentrantChecks = 0;
        bool reentrantSafe = true;
        const auto rejectReentrant = [&] {
            ++reentrantChecks;
            reentrantSafe = controller.busy() && reentrantSafe;
            if (controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000)) reentrantSafe = false;
            if (controller.stop()) reentrantSafe = false;
            if (controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 0, "reentrant-refused"))
                reentrantSafe = false;
        };
        const auto statusReentry = QObject::connect(&controller,
            &NekoGui_sub::ManagedSessionController::statusChanged, &app, rejectReentrant);
        const auto resultReentry = QObject::connect(&controller,
            &NekoGui_sub::ManagedSessionController::reconnectCompleted, &app, rejectReentrant);
        const auto compatibilityReentry = QObject::connect(&controller,
            &NekoGui_sub::ManagedSessionController::reconnectFinished, &app, rejectReentrant);
        const auto operationReentry = QObject::connect(&controller,
            &NekoGui_sub::ManagedSessionController::operationFinished, &app, rejectReentrant);
        completed = false;
        reconnectOutcomeReceived = false;
        const auto beforeReentryCompletions = reconnectCompletions;
        const auto beforeReentryGeneration = ownership.generation(Ownership::Owner::Managed);
        const auto beforeReentryPid = pid;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 0, "reentry-test") ||
            !await() || succeeded || !awaitReconnectOutcome() || !reentrantSafe || reentrantChecks != 4 ||
            controller.busy() || reconnectCompletions != beforeReentryCompletions + 1 ||
            completedRequestId != "reentry-test" ||
            correlatedOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::Rejected) ||
            correlatedSnapshot.value("busy").toBool() || correlatedSnapshot != controller.snapshot() ||
            pid != beforeReentryPid || ownership.generation(Ownership::Owner::Managed) != beforeReentryGeneration) return 101;
        QObject::disconnect(statusReentry);
        QObject::disconnect(resultReentry);
        QObject::disconnect(compatibilityReentry);
        QObject::disconnect(operationReentry);
        QTextStream(stdout) << "MANAGED_COMPLETION_REENTRANT_COMMAND_REFUSAL_PASS checks=4\n";
        completed = false;
        if (!controller.stop() || !await() || !succeeded || group != -1 || pid != 0 || !portsClosed()) return 53;
        if (controller.snapshot().value("controllerReady").toBool() ||
            controller.snapshot().value("state").toString() != "stopped") return 63;
        completed = false;
        if (!controller.start(snapshots.path(), 999, executable, mixedPort, apiPort, 10000) ||
            !await() || succeeded || pid != 0) return 54;
        completed = false;
        if (!controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !await() || !succeeded) return 55;
#ifdef Q_OS_WIN
        bool runtimeFailed = false;
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::runtimeFailed,
            &app, [&](const QString &) { runtimeFailed = true; });
        HANDLE asyncChild = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                                        static_cast<DWORD>(controller.processId()));
        if (!asyncChild) return 57;
        const bool terminated = TerminateProcess(asyncChild, 42) && WaitForSingleObject(asyncChild, 3000) == WAIT_OBJECT_0;
        CloseHandle(asyncChild);
        if (!terminated) return 58;
        QElapsedTimer crashDeadline;
        crashDeadline.start();
        while (!runtimeFailed && crashDeadline.elapsed() < 5000) {
            QEventLoop pause;
            QTimer::singleShot(10, &pause, &QEventLoop::quit);
            pause.exec();
        }
        if (!runtimeFailed || controller.state() != static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Failed) ||
            controller.processId() != 0 || controller.groupId() != -1 || controller.busy() ||
            !portsClosed() || ownership.owner() != Ownership::Owner::None) return 59;
        if (controller.snapshot().value("state").toString() != "failed" ||
            controller.snapshot().value("controllerReady").toBool() ||
            controller.snapshot().value("vpnConnected").toBool()) return 64;
        completed = false;
        if (!controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000) ||
            !await() || !succeeded) return 60;
        QTextStream(stdout) << "MANAGED_ASYNC_UNEXPECTED_EXIT_MONITOR_PASS\n";
#endif
    } // Controller destruction must stop and destroy session on its worker.
    if (!portsClosed() || ownership.owner() != Ownership::Owner::None) return 56;
    QTextStream(stdout) << "MANAGED_ASYNC_WORKER_STATUS_SHUTDOWN_PASS\n";
    {
        int signalCalls = 0;
        NekoGui_sub::ManagedSessionController controller(nullptr, [&signalCalls](qint64 pid) {
            ++signalCalls;
            Q_UNUSED(pid)
            return false; // Refuse graceful signaling; production cleanup must reap the child.
        });
        bool completed = false;
        bool operationSuccess = true;
        QString requestId;
        QString completionError;
        int completionOutcome = -1;
        QJsonObject completionSnapshot;
        int stopFailedCompletions = 0;
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::reconnectCompleted,
            &app, [&](const QString &id, bool success, int outcome, const QString &message,
                      const QJsonObject &snapshot) {
                ++stopFailedCompletions;
                requestId = id;
                operationSuccess = success;
                completionOutcome = outcome;
                completionError = message;
                completionSnapshot = snapshot;
            });
        QObject::connect(&controller, &NekoGui_sub::ManagedSessionController::operationFinished,
            &app, [&](bool, const QString &) { completed = true; });
        auto awaitCompletion = [&] {
            QElapsedTimer deadline;
            deadline.start();
            while (!completed && deadline.elapsed() < 30000) {
                QEventLoop pause;
                QTimer::singleShot(10, &pause, &QEventLoop::quit);
                pause.exec();
            }
            return completed;
        };
        if (!controller.start(snapshots.path(), 71, executable, mixedPort, apiPort, 10000)) return 108;
        QElapsedTimer startDeadline;
        startDeadline.start();
        while (controller.busy() && startDeadline.elapsed() < 30000) {
            QEventLoop pause;
            QTimer::singleShot(10, &pause, &QEventLoop::quit);
            pause.exec();
        }
        if (controller.busy() || controller.state() != static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Ready) ||
            controller.processId() == 0) return 109;
        completed = false;
        if (!controller.reconnect(snapshots.path(), 71, executable, mixedPort, apiPort, 10000, "controller-stop-failed"))
            return 110;
        if (!awaitCompletion() || signalCalls != 1 || operationSuccess || requestId != "controller-stop-failed" ||
            completionOutcome != static_cast<int>(NekoGui_sub::ManagedSession::ReconnectOutcome::StopFailed) ||
            completionError.isEmpty() || stopFailedCompletions != 1 ||
            completionSnapshot.value("state").toString() != "failed" ||
            completionSnapshot.value("groupId").toInt(-1) != -1 || completionSnapshot.value("busy").toBool() ||
            controller.snapshot() != completionSnapshot || controller.processId() != 0 || controller.groupId() != -1 ||
            ownership.owner() != Ownership::Owner::None || !portsClosed() ||
            !store.load(71, saved, error) || saved.source != source) return 111;
        QTextStream(stdout) << "MANAGED_CONTROLLER_STOP_FAILED_CORRELATED_COMPLETION_PASS\n";
    }
    QTextStream(stdout) << "MANAGED_READONLY_SNAPSHOT_CONTRACT_PASS\n";
    return 0;
}
