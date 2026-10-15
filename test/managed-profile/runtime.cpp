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
    QTextStream(stdout) << "MANAGED_READONLY_SNAPSHOT_CONTRACT_PASS\n";
    return 0;
}
