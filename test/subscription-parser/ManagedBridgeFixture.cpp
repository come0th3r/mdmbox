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
#include <QWebChannel>
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
    QWebEngineProfile profile; // Off-the-record; no external HTML/assets.
    QWebEnginePage page(&profile);
    QWebChannel channel;
    channel.registerObject("mdmboxBridge", bridge);
    page.setWebChannel(&channel);
    int phase = 0;
    int startReplies = 0, busyReplies = 0, stopReplies = 0;
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
        else if (id == "js-ready") phase = 1;
        else if (id == "js-stopped") phase = 2;
        else if (id == "js-failed") failed = true;
    });
    QObject::connect(&page, &QWebEnginePage::renderProcessTerminated, &app,
        [&](QWebEnginePage::RenderProcessTerminationStatus, int) { failed = true; });
    const QString script = QStringLiteral(R"HTML(<!doctype html>
        <script src="qrc:///qtwebchannel/qwebchannel.js"></script><script>
        new QWebChannel(qt.webChannelTransport,function(c){
          const b=c.objects.mdmboxBridge;
          b.managedCommandResult.connect(function(id,r){
            if(id==='start' && (!r.accepted || !r.queued || !r.runtime.busy || r.runtime.vpnConnected))
              b.managedStart(null,'js-failed');
          });
          b.managedRuntimeEvent.connect(function(e){
            if(e.type!=='operationFinished'||!e.success||e.runtime.vpnConnected){b.managedStart(null,'js-failed');return;}
            if(e.runtime.state==='ready'&&e.runtime.controllerReady)b.managedStart(null,'js-ready');
            else if(e.runtime.state==='stopped'&&!e.runtime.controllerReady)b.managedStart(null,'js-stopped');
            else b.managedStart(null,'js-failed');
          });
          b.managedStart(%1,'start');b.managedStop('busy');
          window.bridge=b;
        });</script>)HTML").arg(group->id);
    page.setHtml(script, QUrl("qrc:///"));
    if (!await([&] { return phase == 1; }) || startReplies != 1 || busyReplies != 1 ||
        window.shellManagedRuntimeState().value("groupId").toInt(-1) != group->id) return 93;
    // Real entry points must refuse before system side effects.
    window.neko_set_spmode_system_proxy(true);
    window.neko_set_spmode_vpn(true);
    if (NekoGui::dataStore->spmode_system_proxy || NekoGui::dataStore->spmode_vpn ||
        !window.managedBlocksLegacy()) return 94;
    page.runJavaScript("window.bridge.managedStop('stop')");
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
    return 0;
}
