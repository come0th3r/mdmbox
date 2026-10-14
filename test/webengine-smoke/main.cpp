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

int main(int argc, char **argv) {
    QCoreApplication::setAttribute(Qt::AA_ShareOpenGLContexts);
    QApplication app(argc, argv);
    QTemporaryDir directory;
    if (!directory.isValid()) return 2;
    QFile html(directory.filePath(QStringLiteral("smoke.html")));
    if (!html.open(QIODevice::WriteOnly)) return 3;
    html.write("<!doctype html><title>MDMBOX smoke</title>"
               "<p id='result'>MDMBOX_LOCAL_HTML</p>");
    html.close();

    // An unnamed profile is off-the-record: no real user profile or cache.
    QWebEngineProfile profile;
    QWebEnginePage page(&profile);
    QWebChannel channel;
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
            app.exit(0);
        });
    });
    QTimer::singleShot(30000, &app, [&app]() {
        QTextStream(stderr) << "WEBENGINE_SMOKE_TIMEOUT\n";
        app.exit(7);
    });
    page.load(QUrl::fromLocalFile(html.fileName()));
    return app.exec();
}
