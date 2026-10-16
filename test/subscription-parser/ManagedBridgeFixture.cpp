#ifdef _WIN32
#include <windows.h> // Before project enum names and Qt's interface macro.
#endif
#include <QApplication>
#include <QDir>
#include <QTemporaryDir>
#include <QTextStream>
#include <QTimer>
#include "db/Database.hpp"

#include "ui/mainwindow.h"
#include "preview/mdmbox_shell_window.h"
#include "preview/mdmbox_shell_bridge.h"
#include "sub/MihomoValidator.hpp"
#include "sub/ManagedProfileStore.hpp"
#include "sub/ManagedSessionController.hpp"
#include "sub/SubscriptionDownloader.hpp"
#include "ManagedRefreshFixture.hpp"
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QElapsedTimer>
#include <QTcpSocket>
#include <QEventLoop>
#include <QFile>

// Production MainWindow/controller + actual shell bridge, isolated cwd and HTML.
// The test build excludes ONLY automatic legacy core/remembered OS mode startup.
int runManagedBridgeFixture(QApplication &app) {
    QTemporaryDir directory;
    const auto previous = QDir::currentPath();
    struct RestoreDirectory { QString path; ~RestoreDirectory() { QDir::setCurrent(path); } } restore{previous};
    if (!directory.isValid() || !QDir::setCurrent(directory.path())) return 90;
    QDir().mkpath("profiles");
    QDir().mkpath("groups");
    NekoGui::dataStore->flag_tray = true;
    NekoGui::dataStore->remember_enable = false;
    NekoGui::dataStore->remember_spmode.clear();
    NekoGui::dataStore->sub_auto_update = 0;
    MainWindow window;
    auto group = NekoGui::ProfileManager::NewGroup();
    group->name = "synthetic bridge";
    group->subscription_kind = "mihomo-full";
    NekoGui::profileManager->AddGroup(group);
    const QByteArray source = "proxies: [{name: node, type: socks5, server: 127.0.0.1, port: 12345}]\n"
        "proxy-groups: [{name: select, type: select, proxies: [node]}]\nrules: ['MATCH,DIRECT']\n"
        "dns: {enable: false, nameserver: [127.0.0.1]}\n";
    const QString executable = QCoreApplication::applicationDirPath() + "/mihomo.exe";
    QString error;
    NekoGui_sub::ManagedProfileStore store("managed-subscriptions");
    NekoGui_sub::ManagedProfile saved;
    if (!store.commit(group->id, source, [&](const NekoGui_sub::ManagedProfile &profile, QString &e) {
        return NekoGui_sub::MihomoValidator::validate(executable, profile, e);
    }, error)) { QTextStream(stderr) << "BRIDGE_SNAPSHOT_FAILED " << error << "\n"; return 91; }

    const auto arguments = app.arguments();
    const auto fixtureIndex = arguments.indexOf(QStringLiteral("--managed-bridge-e2e"));
    if (fixtureIndex < 0 || fixtureIndex + 2 >= arguments.size()) return 114;
    QFile certFile(arguments.at(fixtureIndex + 1)), keyFile(arguments.at(fixtureIndex + 2));
    if (!QSslSocket::supportsSsl() || !certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) return 115;
    ManagedRefreshFixture httpsServer;
    httpsServer.certificate = QSslCertificate(certFile.readAll());
    httpsServer.key = QSslKey(keyFile.readAll(), QSsl::Rsa);
    if (httpsServer.certificate.isNull() || httpsServer.key.isNull() ||
        !httpsServer.listen(QHostAddress::LocalHost, 0)) return 116;
    NekoGui_sub::SubscriptionDownloader::setTestCaCertificates({httpsServer.certificate});
    struct RestoreFixtureTrust {
        ~RestoreFixtureTrust() { NekoGui_sub::SubscriptionDownloader::clearTestCaCertificates(); }
    } restoreTrust;

    MdmBoxShellWindow shell(nullptr, false); // Core E2E uses a controlled synthetic WebEngine page.
    auto *bridge = shell.findChild<MdmBoxShellBridge *>();
    if (!bridge) return 92;
    auto *view = shell.findChild<QWebEngineView *>();
    if (!view || !view->page()->profile()->isOffTheRecord()) return 98;
    auto &page = *view->page(); // Actual production hookPage/channel, synthetic local HTML only.
    int phase = 0;
    int startReplies = 0, busyReplies = 0, stopReplies = 0;
    int readyEvents = 0, stoppedEvents = 0, crashEvents = 0, loadedPages = 0;
    int restoredReady = 0;
    int reconnectReplies = 0, reconnectEvents = 0, refusedReconnectReplies = 0;
    int refreshReplies = 0, refreshEvents = 0, refreshFailureEvents = 0, duplicateRefreshCompletions = 0;
    int refreshOperationCompletions = 0;
    int refreshControllerCompletions = 0;
    bool lastRefreshSuccess = false;
    int lastRefreshOutcome = -1;
    int rejectedReplies = 0, rejectedEvents = 0;
    bool failed = false;
    auto await = [&](const std::function<bool()> &condition) {
        QElapsedTimer timer;
        timer.start();
        while (!condition() && !failed && timer.elapsed() < 20000) {
            QEventLoop pause;
            QTimer::singleShot(10, &pause, &QEventLoop::quit);
            pause.exec();
        }
        return !failed && condition();
    };
    QObject::connect(bridge, &MdmBoxShellBridge::managedCommandResult, &app,
        [&](const QString &id, const QJsonObject &r) {
        if (id == "start") { ++startReplies; if (!r.value("accepted").toBool()) failed = true; }
        else if (id == "busy") { ++busyReplies; if (r.value("accepted").toBool()) failed = true; }
        else if (id == "stop") { ++stopReplies; if (!r.value("accepted").toBool()) failed = true; }
        else if (id == "js-ready") { phase = 1; ++readyEvents; }
        else if (id == "js-stopped") { phase = 2; ++stoppedEvents; }
        else if (id == "js-crashed") { phase = 3; ++crashEvents; }
        else if (id == "js-loaded") ++loadedPages;
        else if (id == "js-restored-ready") ++restoredReady;
        else if (id == "reconnect") { ++reconnectReplies; if (!r.value("accepted").toBool()) failed = true; }
        else if (id == "reconnect-busy" || id == "reconnect-invalid" || id == "reconnect-inactive") {
            ++refusedReconnectReplies; if (r.value("accepted").toBool()) failed = true;
        }
        else if (id == "js-reconnected") ++reconnectEvents;
        else if (id == "reconnect-rejected") { ++rejectedReplies; if (!r.value("accepted").toBool()) failed = true; }
        else if (id == "refresh") { ++refreshReplies; if (!r.value("accepted").toBool()) failed = true; }
        else if (id == "refresh-failed") {
            ++refreshReplies;
            if (!r.value("accepted").toBool() || !r.value("queued").toBool() ||
                !r.value("runtime").toObject().value("busy").toBool()) failed = true;
        }
        else if (id == "js-refresh-failed") ++refreshFailureEvents;
        else if (id == "js-refresh-duplicate") ++duplicateRefreshCompletions;
        else if (id == "js-reconnect-rejected") ++rejectedEvents;
        else if (id == "js-refreshed") ++refreshEvents;
        else if (id == "js-failed") failed = true;
    });
    QObject::connect(&page, &QWebEnginePage::renderProcessTerminated, &app,
        [&](QWebEnginePage::RenderProcessTerminationStatus, int) { failed = true; });
    const QString script = QStringLiteral(R"HTML(<!doctype html><script>
        window.addEventListener('mdmbox-managed-snapshot',function(event){
          const r=event.detail;
          if(r.schemaVersion!==1||r.scope!=='loopback-only'||r.vpnConnected){
            window.mdmboxManaged.start(null,'js-failed');return;
          }
          if(r.state==='ready'&&r.controllerReady)
            window.mdmboxManaged.start(null,'js-restored-ready');
        });
        window.addEventListener('mdmbox-managed-command-result',function(event){
            const id=event.detail.requestId,r=event.detail.result;
            if(id==='start' && (!r.accepted || !r.queued || !r.runtime.busy || r.runtime.vpnConnected))
               window.mdmboxManaged.start(null,'js-failed');
            if(((id==='refresh'||id==='refresh-failed') &&
                (!r.accepted || !r.queued || !r.runtime.busy || r.runtime.vpnConnected)))
               window.mdmboxManaged.start(null,'js-failed');
        });
        window.addEventListener('mdmbox-managed-runtime',function(event){
            const e=event.detail,m=window.mdmboxManaged;
            if(e.schemaVersion!==1||e.runtime.vpnConnected){m.start(null,'js-failed');return;}
            if(e.type==='refreshCompleted'){
              if(e.command!=='managedRefresh'||!e.runtime.controllerReady||e.runtime.state!=='ready'){
                m.start(null,'js-failed');return;
              }
              if(e.requestId==='refresh-failed'){
                if(e.success||e.outcome!=='rejected'||!e.error){m.start(null,'js-failed');return;}
                m.start(null,'js-refresh-failed');return;
              }
              if(e.requestId!=='refresh'||!e.success||e.outcome!=='applied'||e.error!==''){
                m.start(null,'js-failed');return;
              }
              m.start(null,'js-refreshed');return;
            }
            if(e.type==='operationFinished'&&e.command==='managedRefresh'){
              m.start(null,'js-refresh-duplicate');return;
            }
            if(e.type==='reconnectCompleted'){
              if(e.requestId==='reconnect-rejected'){
                if(e.command!=='managedReconnect'||e.success||e.outcome!=='rejected'||!e.error||
                   e.runtime.state!=='ready'||!e.runtime.controllerReady)m.start(null,'js-failed');
                else m.start(null,'js-reconnect-rejected');
                return;
              }
              if(e.requestId!=='reconnect'||e.command!=='managedReconnect'||!e.success||
                 e.outcome!=='applied'||e.error!==''||e.runtime.state!=='ready'||!e.runtime.controllerReady)
                m.start(null,'js-failed');
              else m.start(null,'js-reconnected');
              return;
            }
            if(e.type==='operationFinished'&&
              ((e.runtime.state==='ready'&&(e.requestId!=='start'||e.command!=='managedStart'))||
               (e.runtime.state==='stopped'&&(e.requestId!=='stop'||e.command!=='managedStop')))){
                m.start(null,'js-failed');return;
            }
            if(e.type==='runtimeFailed'&&!e.success&&e.runtime.state==='failed'&&!e.runtime.controllerReady)
              m.start(null,'js-crashed');
            else if(e.type!=='operationFinished'||!e.success)m.start(null,'js-failed');
            else if(e.runtime.state==='ready'&&e.runtime.controllerReady)m.start(null,'js-ready');
            else if(e.runtime.state==='stopped'&&!e.runtime.controllerReady)m.start(null,'js-stopped');
            else m.start(null,'js-failed');
        });
        const boot=setInterval(function(){if(!window.mdmboxManaged)return;
          clearInterval(boot);window.mdmboxManaged.start(null,'js-loaded');
        },10);
        </script>)HTML");
    page.setHtml(script, QUrl("qrc:///"));
    if (!await([&] { return loadedPages == 1; })) return 99;
    page.runJavaScript(QString("window.mdmboxManaged.reconnect(%1,'reconnect-inactive');window.mdmboxManaged.reconnect(null,'reconnect-invalid')").arg(group->id));
    if (!await([&] { return refusedReconnectReplies == 2; })) return 106;
    // Repeated hook calls must not duplicate signal bindings.
    shell.hookPage();
    shell.hookPage();
    page.runJavaScript(QString("window.mdmboxManaged.start(%1,'start');window.mdmboxManaged.stop('busy')").arg(group->id));
    if (!await([&] { return phase == 1; }) || startReplies != 1 || busyReplies != 1 ||
        window.shellManagedRuntimeState().value("groupId").toInt(-1) != group->id) return 93;
    // Real entry points must refuse before system side effects.
    window.neko_set_spmode_system_proxy(true);
    window.neko_set_spmode_vpn(true);
    if (NekoGui::dataStore->spmode_system_proxy || NekoGui::dataStore->spmode_vpn ||
        !window.managedBlocksLegacy()) return 94;
    // Recreate JS context while the real core remains active. No implicit Start.
    page.setHtml(script, QUrl("qrc:///"));
    if (!await([&] { return loadedPages == 2 && restoredReady == 2; }) || readyEvents != 1 ||
        !window.shellManagedRuntimeState().value("controllerReady").toBool()) return 100;
    auto *reconnectController = window.findChild<NekoGui_sub::ManagedSessionController *>();
    if (!reconnectController) return 107;
    QObject::connect(reconnectController, &NekoGui_sub::ManagedSessionController::operationFinished,
                     &app, [&](bool, const QString &) { ++refreshOperationCompletions; });
    QObject::connect(reconnectController, &NekoGui_sub::ManagedSessionController::refreshCompleted,
                     &app, [&](const QString &, bool success, int outcome, const QString &, const QJsonObject &) {
        ++refreshControllerCompletions;
        lastRefreshSuccess = success;
        lastRefreshOutcome = outcome;
    });
    const auto oldGeneration = NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed);
    page.runJavaScript(QString("window.mdmboxManaged.reconnect(%1,'reconnect');window.mdmboxManaged.reconnect(%1,'reconnect-busy')").arg(group->id));
    if (!await([&] { return reconnectEvents == 1; }) || reconnectReplies != 1 || refusedReconnectReplies != 3 ||
        readyEvents != 1 || reconnectController->processId() <= 0 ||
        NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed) <= oldGeneration) return 108;
    const auto preservedPid = reconnectController->processId();
    const auto preservedGeneration = NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed);
    const auto resourceCandidate = source + "rule-providers: {external: {type: http, url: 'https://example.invalid/rules', path: rules.yaml}}\n";
    if (!store.commit(group->id, resourceCandidate,
        [](const NekoGui_sub::ManagedProfile &, QString &) { return true; }, error)) return 110;
    page.runJavaScript(QString("window.mdmboxManaged.reconnect(%1,'reconnect-rejected')").arg(group->id));
    if (!await([&] { return rejectedEvents == 1; }) || rejectedReplies != 1 ||
        reconnectController->processId() != preservedPid ||
        NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed) != preservedGeneration) return 111;
    if (!store.commit(group->id, source, [&](const NekoGui_sub::ManagedProfile &profile, QString &e) {
        return NekoGui_sub::MihomoValidator::validate(executable, profile, e);
    }, error)) return 112;
    const int operationCompletionsBeforeRefresh = refreshOperationCompletions;
    const int controllerCompletionsBeforeRefresh = refreshControllerCompletions;
    const auto refreshedSource = source + "# synthetic HTTPS refresh\n";
    httpsServer.body = refreshedSource;
    group->url = QString("https://localhost:%1/synthetic?keep=bridge&format=uri")
        .arg(httpsServer.serverPort());
    group->Save();
    page.runJavaScript(QString("window.mdmboxManaged.refreshSubscription(%1,'refresh')").arg(group->id));
    if (!await([&] { return refreshEvents == 1 && !reconnectController->busy(); }) ||
        refreshReplies != 1 || httpsServer.requests != 1 ||
        reconnectController->processId() <= 0 ||
        NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed) <= preservedGeneration) return 117;
    const auto refreshHeaders = httpsServer.lastRequest.toLower();
    if (!refreshHeaders.contains("user-agent: mdmbox/") || !refreshHeaders.contains("x-hwid:") ||
        !httpsServer.lastRequest.contains("format=clash") || !store.load(group->id, saved, error) ||
        saved.source != refreshedSource) return 118;
    const auto readyPid = reconnectController->processId();
    const auto readyGeneration = NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed);
    httpsServer.expiry = 1; // Real HTTP 200, rejected after fetch before validation or commit.
    page.runJavaScript(QString("window.mdmboxManaged.refreshSubscription(%1,'refresh-failed')").arg(group->id));
    const bool failureEvent = await([&] { return refreshFailureEvents == 1 && !reconnectController->busy(); });
    const bool preservedSnapshot = store.load(group->id, saved, error) && saved.source == refreshedSource;
    if (!failureEvent || refreshReplies != 2 || httpsServer.requests != 2 ||
        refreshOperationCompletions - operationCompletionsBeforeRefresh != 2 ||
        refreshControllerCompletions - controllerCompletionsBeforeRefresh != 2 ||
        reconnectController->processId() != readyPid ||
        NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed) != readyGeneration ||
        !preservedSnapshot) {
        QTextStream(stderr) << "REFRESH_REJECTION_DIAGNOSTIC event=" << refreshFailureEvents
            << " replies=" << refreshReplies << " requests=" << httpsServer.requests
            << " opCompletions=" << refreshOperationCompletions
            << " refreshCompletions=" << refreshControllerCompletions
            << " lastSuccess=" << lastRefreshSuccess << " lastOutcome=" << lastRefreshOutcome
            << " busy=" << reconnectController->busy()
            << " stateReady=" << (reconnectController->state() == static_cast<int>(NekoGui_sub::ManagedCoreProcess::State::Ready))
            << " controllerGroup=" << reconnectController->groupId() << " requestedGroup=" << group->id
            << " samePid=" << (reconnectController->processId() == readyPid)
            << " sameGeneration=" << (NekoGui_sub::CoreOwnership::shared().generation(NekoGui_sub::CoreOwnership::Owner::Managed) == readyGeneration)
            << " sameSnapshot=" << preservedSnapshot << "\n";
        return 120;
    }
#ifdef Q_OS_WIN
    auto *controller = window.findChild<NekoGui_sub::ManagedSessionController *>();
    if (!controller || controller->processId() <= 0) return 101;
    HANDLE child = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                               static_cast<DWORD>(controller->processId()));
    if (!child) return 102;
    const bool terminated = TerminateProcess(child, 42) && WaitForSingleObject(child, 3000) == WAIT_OBJECT_0;
    CloseHandle(child);
    if (!terminated || !await([&] { return phase == 3; }) || crashEvents != 1 ||
        controller->processId() != 0 || window.managedBlocksLegacy() ||
        window.shellManagedRuntimeState().value("state").toString() != "failed") return 103;
    page.runJavaScript(QString("window.mdmboxManaged.start(%1,'start')").arg(group->id));
    if (!await([&] { return phase == 1; }) || startReplies != 2 || readyEvents != 2) return 104;
#endif
    page.runJavaScript("window.mdmboxManaged.stop('stop')");
    if (!await([&] { return phase == 2; }) || stopReplies != 1) return 95;
    for (int port : {17890, 19090}) {
        QTcpSocket socket;
        socket.connectToHost(QHostAddress::LocalHost, port);
        if (socket.waitForConnected(250)) return 96;
    }
    if (!store.load(group->id, saved, error) || saved.source != refreshedSource || window.managedBlocksLegacy() ||
        NekoGui_sub::CoreOwnership::shared().owner() != NekoGui_sub::CoreOwnership::Owner::None) return 97;
    QTextStream(stdout) << "MANAGED_PRODUCTION_BRIDGE_JS_START_BUSY_READY_STOP_PASS\n";
    if (stoppedEvents != 1) return 105;
    QTextStream(stdout) << "MANAGED_PRODUCTION_HOOK_CUSTOM_EVENT_RELOAD_PASS\n";
    QTextStream(stdout) << "MANAGED_PRODUCTION_RELOAD_READY_SNAPSHOT_RESYNC_PASS\n";
    if (reconnectEvents != 1) return 109;
    QTextStream(stdout) << "MANAGED_PRODUCTION_BRIDGE_RECONNECT_CORRELATED_APPLIED_PASS\n";
    if (rejectedEvents != 1) return 113;
    QTextStream(stdout) << "MANAGED_PRODUCTION_BRIDGE_RECONNECT_REJECTED_RETAINS_READY_PASS\n";
    if (refreshEvents != 1 || refreshFailureEvents != 1 || duplicateRefreshCompletions != 0 ||
        refreshReplies != 2 || httpsServer.requests != 2) return 119;
    QTextStream(stdout) << "MANAGED_PRODUCTION_BRIDGE_HTTPS_REFRESH_VALIDATE_COMMIT_APPLY_AND_REJECT_PRESERVATION_PASS\n";
#ifdef Q_OS_WIN
    QTextStream(stdout) << "MANAGED_PRODUCTION_CRASH_JS_FAILED_RESTART_PASS\n";
#endif
    return 0;
}
