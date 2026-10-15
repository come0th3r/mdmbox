#include <QApplication>
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>
#include <QTimer>
#include <QUrl>
#include <QVariant>
#include <QWebChannel>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include "../../sub/ManagedCommandContract.hpp"

class SmokeBridge : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE QString echo(const QString &value) {
        return QStringLiteral("cpp:") + value;
    }
    Q_INVOKABLE void complete(const QString &value) {
        emit completed(value == QStringLiteral("cpp:MDMBOX_LOCAL_HTML:42"));
    }
    Q_INVOKABLE void managedStart(const QJsonValue &value, const QString &requestId) {
        int id = -1;
        const bool valid = NekoGui_sub::ManagedCommandContract::groupId(value, id);
        // Contract-only fixture: never launches a process or touches system modes.
        emit managedCommandResult(requestId, NekoGui_sub::ManagedCommandContract::result(
            QStringLiteral("managedStart"), false,
            valid ? QStringLiteral("Fixture refuses launch") : QStringLiteral("Invalid group ID"),
            {{QStringLiteral("vpnConnected"), false}, {QStringLiteral("groupId"), id}}));
    }
    Q_INVOKABLE void contractComplete(bool success) {
        emit contractCompleted(success);
    }
signals:
    void completed(bool success);
    void contractCompleted(bool success);
    void managedCommandResult(const QString &requestId, const QJsonObject &result);
};

int main(int argc, char **argv) {
    QCoreApplication::setAttribute(Qt::AA_ShareOpenGLContexts);
    QApplication app(argc, argv);
    QTemporaryDir directory;
    if (!directory.isValid()) return 2;
    QFile html(directory.filePath(QStringLiteral("smoke.html")));
    if (!html.open(QIODevice::WriteOnly)) return 3;
    html.write("<!doctype html><title>MDMBOX smoke</title>"
               "<p id='result'>MDMBOX_LOCAL_HTML</p>"
               "<script src='qrc:///qtwebchannel/qwebchannel.js'></script>"
               "<script>window.addEventListener('load', function() {"
               "new QWebChannel(qt.webChannelTransport, function(channel) {"
                "const bridge = channel.objects.smoke;"
                "const values=[null,true,'71',-1,1.5,2147483648,{},[],71,0];let index=0;"
                "bridge.managedCommandResult.connect(function(id,r){"
                "const valid=index>=8;const ok=id==='r'+index&&r.schemaVersion===1&&"
                "r.command==='managedStart'&&!r.accepted&&!r.queued&&r.runtime.vpnConnected===false&&"
                "r.error===(valid?'Fixture refuses launch':'Invalid group ID')&&"
                "r.runtime.groupId===(valid?values[index]:-1);"
                "if(!ok){bridge.contractComplete(false);return;}"
                "if(++index===values.length){bridge.contractComplete(true);return;}"
                "bridge.managedStart(values[index],'r'+index);});"
                "bridge.managedStart(values[index],'r'+index);"
               "bridge.echo(document.getElementById('result').textContent + ':' + (6 * 7),"
               "function(reply) { bridge.complete(reply); });"
               "}); });</script>");
    html.close();

    // An unnamed profile is off-the-record: no real user profile or cache.
    QWebEngineProfile profile;
    QWebEnginePage page(&profile);
    QWebChannel channel;
    SmokeBridge bridge;
    bool echoPassed = false, contractPassed = false;
    channel.registerObject(QStringLiteral("smoke"), &bridge);
    QObject::connect(&bridge, &SmokeBridge::completed, &app, [&](bool success) {
        if (!success) { app.exit(8); return; }
        QTextStream(stdout) << "WEBENGINE_QWEBCHANNEL_ROUNDTRIP_PASS Qt=" << qVersion() << "\n";
        echoPassed = true;
        if (contractPassed) app.exit(0);
    });
    QObject::connect(&bridge, &SmokeBridge::contractCompleted, &app, [&](bool success) {
        if (!success) { app.exit(9); return; }
        contractPassed = true;
        QTextStream(stdout) << "MANAGED_COMMAND_JSON_WEBCHANNEL_CONTRACT_PASS cases=10\n";
        if (echoPassed) app.exit(0);
    });
    page.setWebChannel(&channel);
    QObject::connect(&page, &QWebEnginePage::renderProcessTerminated, &app,
                     [&app](QWebEnginePage::RenderProcessTerminationStatus, int) {
        QTextStream(stderr) << "WEBENGINE_RENDER_PROCESS_FAILED\n";
        app.exit(4);
    });
    QObject::connect(&page, &QWebEnginePage::loadFinished, &app, [&](bool ok) {
        if (!ok) { app.exit(5); return; }
        page.runJavaScript(QStringLiteral("document.getElementById('result').textContent + ':' + (6 * 7)"),
                           [&](const QVariant &value) {
            if (value.toString() != QStringLiteral("MDMBOX_LOCAL_HTML:42")) {
                app.exit(6);
                return;
            }
            QTextStream(stdout) << "WEBENGINE_LOCAL_HTML_JS_PASS Qt=" << qVersion() << "\n";
        });
    });
    QTimer::singleShot(30000, &app, [&app]() {
        QTextStream(stderr) << "WEBENGINE_SMOKE_TIMEOUT\n";
        app.exit(7);
    });
    page.load(QUrl::fromLocalFile(html.fileName()));
    return app.exec();
}

#include "main.moc"
