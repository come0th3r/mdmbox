#ifdef _WIN32
#include <windows.h> // Before project enum names and Qt's interface macro.
#endif
#include <QApplication>
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
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QElapsedTimer>
#include <QTcpSocket>
#include <QEventLoop>

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
    if (!store.commit(group->id, source, [&](const NekoGui_sub::ManagedProfile &profile, QString &e) {
        return NekoGui_sub::MihomoValidator::validate(executable, profile, e);
    }, error)) { QTextStream(stderr) << "BRIDGE_SNAPSHOT_FAILED " << error << "\n"; return 91; }

    MdmBoxShellWindow shell(nullptr, false); // Do not load design HTML/remote assets.
    auto *bridge = shell.findChild<MdmBoxShellBridge *>();
    if (!bridge) return 92;
    auto *view = shell.findChild<QWebEngineView *>();
    if (!view || !view->page()->profile()->isOffTheRecord()) return 98;
    auto &page = *view->page(); // Actual production hookPage/channel, local HTML only.
    int phase = 0;
    int startReplies = 0, busyReplies = 0, stopReplies = 0;
    int readyEvents = 0, stoppedEvents = 0, crashEvents = 0, loadedPages = 0;
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
        else if (id == "js-failed") failed = true;
    });
    QObject::connect(&page, &QWebEnginePage::renderProcessTerminated, &app,
        [&](QWebEnginePage::RenderProcessTerminationStatus, int) { failed = true; });
    const QString script = QStringLiteral(R"HTML(<!doctype html><script>
        window.addEventListener('mdmbox-managed-command-result',function(event){
            const id=event.detail.requestId,r=event.detail.result;
            if(id==='start' && (!r.accepted || !r.queued || !r.runtime.busy || r.runtime.vpnConnected))
               window.mdmboxManaged.start(null,'js-failed');
        });
        window.addEventListener('mdmbox-managed-runtime',function(event){
            const e=event.detail,m=window.mdmboxManaged;
            if(e.schemaVersion!==1||e.runtime.vpnConnected){m.start(null,'js-failed');return;}
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
    if (!await([&] { return loadedPages == 2; }) || readyEvents != 1 ||
        !window.shellManagedRuntimeState().value("controllerReady").toBool()) return 100;
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
    NekoGui_sub::ManagedProfile saved;
    if (!store.load(group->id, saved, error) || saved.source != source || window.managedBlocksLegacy() ||
        NekoGui_sub::CoreOwnership::shared().owner() != NekoGui_sub::CoreOwnership::Owner::None) return 97;
    QTextStream(stdout) << "MANAGED_PRODUCTION_BRIDGE_JS_START_BUSY_READY_STOP_PASS\n";
    if (stoppedEvents != 1) return 105;
    QTextStream(stdout) << "MANAGED_PRODUCTION_HOOK_CUSTOM_EVENT_RELOAD_PASS\n";
#ifdef Q_OS_WIN
    QTextStream(stdout) << "MANAGED_PRODUCTION_CRASH_JS_FAILED_RESTART_PASS\n";
#endif
    return 0;
}
